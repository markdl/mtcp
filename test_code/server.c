#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <dirent.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ssl_functions.h>

#include <sched.h>

#ifndef USE_LINUX
#include <mtcp_api.h>
#include <mtcp_epoll.h>
#else
#include <sys/epoll.h>
#endif

#include "cpu.h"
#include "http_parsing.h"
#include "netlib.h"
#include "debug.h"

#include "hashmap.h"

#ifndef USE_LINUX
#define MAX_FLOW_NUM	 (10000)
#else
#define MAX_FLOW_NUM	 (65535)
#endif

#define RCVBUF_SIZE (2*1024)
#define SNDBUF_SIZE (8*1024)

#define MAX_EVENTS (MAX_FLOW_NUM * 3)

#define HTTP_HEADER_LEN 1024
#define URL_LEN 128

#define MAX_FILES 30

#define NAME_LIMIT 128
#define FULLNAME_LIMIT 256

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define HT_SUPPORT FALSE

#define PORT 4433

/*----------------------------------------------------------------------------*/
struct ssl_connection {
	SSL *ssl;
	int accepted;
};
/*----------------------------------------------------------------------------*/
struct file_cache
{
	char name[NAME_LIMIT];
	char fullname[FULLNAME_LIMIT];
	uint64_t size;
	char *file;
};
/*----------------------------------------------------------------------------*/
struct server_vars
{
	char request[HTTP_HEADER_LEN];
	int recv_len;
	int request_len;
	long int total_read, total_sent;
	uint8_t done;
	uint8_t rspheader_sent;
	uint8_t keep_alive;

	int fidx;						// file cache index
	char fname[NAME_LIMIT];  	// file name
	long int fsize;				// file size
};
/*----------------------------------------------------------------------------*/
struct thread_context
{
#ifndef USE_LINUX
	mctx_t mctx;
#endif
	int ep;
	hashmap_t ssl_ctx_map;
	struct server_vars *svars;
};
/*----------------------------------------------------------------------------*/
static int num_cores;
static int core_limit;
static pthread_t app_thread[MAX_CPUS];
static int done[MAX_CPUS];
static char *conf_file = NULL;
static int backlog = -1;
#ifndef USE_LINUX
static mctx_t g_mctx[MAX_CPUS];
#else
static int linux_listener = -1;
#endif
static int use_lock = 0;
/*----------------------------------------------------------------------------*/
const char *www_main;
static struct file_cache fcache[MAX_FILES];
static int nfiles;
/*----------------------------------------------------------------------------*/
static int finished;
/*----------------------------------------------------------------------------*/
#ifdef USE_LINUX
static pthread_mutex_t startup_lock;
#endif
/*----------------------------------------------------------------------------*/
int set_nonblocking(int fd) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		perror("fcntl get");
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
		perror("fcntl set");
		return -1;
	}
	return 0;
}
/*----------------------------------------------------------------------------*/
void
CleanServerVariable(struct server_vars *sv)
{
	sv->recv_len = 0;
	sv->request_len = 0;
	sv->total_read = 0;
	sv->total_sent = 0;
	sv->done = 0;
	sv->rspheader_sent = 0;
	sv->keep_alive = 0;
}
/*----------------------------------------------------------------------------*/
void 
CloseConnection(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
#ifndef USE_LINUX
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
#endif
	struct ssl_connection *conn = hashmap_remove(ctx->ssl_ctx_map, &sockid, NULL);
	SSL_free(conn->ssl);
	free(conn);
#ifndef USE_LINUX
	mtcp_close(ctx->mctx, sockid);
#else
	close(sockid);
#endif
	fprintf(stderr, "[CPU %d] Closed connection on socket %d\n", sched_getcpu(), sockid);
}
/*----------------------------------------------------------------------------*/
static int 
SendUntilAvailable(struct thread_context *ctx, int sockid, struct server_vars *sv)
{
	int ret;
	int sent;
	int len;

	if (sv->done || !sv->rspheader_sent) {
		return 0;
	}

	sent = 0;
	ret = 1;
	while (ret > 0) {
		len = MIN(SNDBUF_SIZE, sv->fsize - sv->total_sent);
		if (len <= 0) {
			break;
		}
		struct ssl_connection *conn = hashmap_get(ctx->ssl_ctx_map, &sockid);
		if (!conn) {
			fprintf(stderr, "Failed to find ssl object to write to connection %d\n", sockid);
			return -1;
		}
		if (!conn->accepted) {
			fprintf(stderr, "Attempted to write to connection before SSL handshake completed on connection %d\n", sockid);
		}
		ret = SSL_write(conn->ssl, fcache[sv->fidx].file + sv->total_sent, len);
		if (ret < 0) {
			fprintf(stderr, "Connection closed with client.\n");
			break;
		}
		sent += ret;
		sv->total_sent += ret;
	}

	if (sv->total_sent >= fcache[sv->fidx].size) {
		sv->done = TRUE;
		finished++;

		if (sv->keep_alive) {
			/* if keep-alive connection, wait for the incoming request */
#ifndef USE_LINUX
			struct mtcp_epoll_event ev;
			ev.events = MTCP_EPOLLIN;
			ev.data.sockid = sockid;
			mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
#else
			struct epoll_event ev;
			ev.data.fd = sockid;
			ev.events = EPOLLIN | EPOLLOUT;
			epoll_ctl(ctx->ep, EPOLL_CTL_MOD, sockid, &ev);
#endif

			CleanServerVariable(sv);
		} else {
			/* else, close connection */
			CloseConnection(ctx, sockid, sv);
		}
	}

	return sent;
}
/*----------------------------------------------------------------------------*/
static char *
StatusCodeToString(int scode)
{
	switch (scode) {
	case 200:
		return "OK";
		break;

	case 404:
		return "Not Found";
		break;
	}

	return NULL;
}
/*----------------------------------------------------------------------------*/
static int 
HandleReadEvent(struct thread_context *ctx, SSL_CTX *ssl_ctx, int sockid, struct server_vars *sv)
{
	char buf[HTTP_HEADER_LEN];
	char url[URL_LEN];
	char response[HTTP_HEADER_LEN];
	time_t t_now;
	char t_str[128];
	char keepalive_str[128];
	int rd;
	int i;
	int len;
	int sent;

	/* HTTP request handling */
	int ssl_found;
	struct ssl_connection *conn = hashmap_find(ctx->ssl_ctx_map, &sockid, &ssl_found);
	if (!conn) {
		conn = (struct ssl_connection *) malloc(sizeof(struct ssl_connection));
		if (!conn) {
			perror("malloc");
			abort();
		}
		conn->accepted = 0;
		
		// Create the SSL object and override the read/write functions
		conn->ssl = ssl_new_connection(ssl_ctx, sockid);

		int *sid = (int *) malloc(sizeof(int));
		*sid = sockid;
		hashmap_put(ctx->ssl_ctx_map, sid, conn);
	}

	if (!conn->accepted) {
		// Now attempt SSL handshake
		rd = SSL_accept(conn->ssl);
		if (rd <= 0) {
			int err = SSL_get_error(conn->ssl, rd);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				return 1;
			}
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "Socket %d: SSL handshake failed\n", sockid);
			return -2;
		}
		conn->accepted = 1;
		return 1;
	}
	
	rd = SSL_read(conn->ssl, &buf, HTTP_HEADER_LEN);
	if (rd <= 0) {
		return rd;
	}
	memcpy(sv->request + sv->recv_len, 
			 (char *)buf, MIN(rd, HTTP_HEADER_LEN - sv->recv_len));
	sv->recv_len += rd;
	sv->request_len = find_http_header(sv->request, sv->recv_len);
	if (sv->request_len <= 0) {
		fprintf(stderr, "Socket %d: Failed to parse HTTP request header.\n"
						"read bytes: %d, recv_len: %d, "
						"request_len: %d, strlen: %ld, request: \n%s\n", 
						sockid, rd, sv->recv_len, 
						sv->request_len, strlen(sv->request), sv->request);
		return rd;
	}

	http_get_url(sv->request, sv->request_len, url, URL_LEN);
	sprintf(sv->fname, "%s%s", www_main, url);

	sv->keep_alive = FALSE;
	if (http_header_str_val(sv->request, "Connection: ", 
									strlen("Connection: "), keepalive_str, 128)) {	
		if (strstr(keepalive_str, "Keep-Alive")) {
			sv->keep_alive = TRUE;
		} else if (strstr(keepalive_str, "Close")) {
			sv->keep_alive = FALSE;
		}
	}

	/* Find file in cache */
	int scode = 404;
	for (i = 0; i < nfiles; i++) {
		if (strcmp(sv->fname, fcache[i].fullname) == 0) {
			sv->fsize = fcache[i].size;
			sv->fidx = i;
			scode = 200;
			break;
		}
	}
	
	/* Response header handling */
	time(&t_now);
	strftime(t_str, 128, "%a, %d %b %Y %X GMT", gmtime(&t_now));
	if (sv->keep_alive)
		sprintf(keepalive_str, "Keep-Alive");
	else
		sprintf(keepalive_str, "Close");

	sprintf(response, "HTTP/1.1 %d %s\r\n"
			  "Date: %s\r\n"
			  "Server: Webserver on Middlebox TCP (Ubuntu)\r\n"
			  "Content-Length: %ld\r\n"
			  "Connection: %s\r\n\r\n",
			  scode, StatusCodeToString(scode), t_str, sv->fsize, keepalive_str);
	len = strlen(response);
	fprintf(stderr, "Socket %d HTTP Response: \n%s", sockid, response);
	sent = SSL_write(conn->ssl, response, len);
	fprintf(stderr, "Socket %d Sent response header: try: %d, sent: %d\n",
				 sockid, len, sent);
	assert(sent == len);
	sv->rspheader_sent = TRUE;
	
#ifndef USE_LINUX
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
#else
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = sockid;
	if (epoll_ctl(ctx->ep, EPOLL_CTL_MOD, sockid, &ev) == -1) {
		perror("epoll_ctl");
		abort();
	}
#endif

	SendUntilAvailable(ctx, sockid, sv);
	
	return rd;
}
/*----------------------------------------------------------------------------*/
int 
AcceptConnection(struct thread_context *ctx, SSL_CTX *ssl_ctx, int listener)
{
#ifndef USE_LINUX
	mctx_t mctx = ctx->mctx;
	int c = mtcp_accept(mctx, listener, NULL, NULL);
#else
	int c = accept(listener, NULL, NULL);
#endif

	if (c >= 0) {
		if (c >= MAX_FLOW_NUM) {
			fprintf(stderr, "Invalid socket id %d.\n", c);
			return -1;
		}

		struct server_vars *sv = &ctx->svars[c];
		CleanServerVariable(sv);

#ifndef USE_LINUX
		mtcp_setsock_nonblock(ctx->mctx, c);
		struct mtcp_epoll_event ev;
		ev.events = MTCP_EPOLLIN;
		ev.data.sockid = c;
		mtcp_epoll_ctl(mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
#else
		if (set_nonblocking(c) < 0) {
			abort();
		}
		struct epoll_event ev;
		ev.events = EPOLLIN | EPOLLET;
		ev.data.fd = c;
		if (epoll_ctl(ctx->ep, EPOLL_CTL_ADD, c, &ev) == -1) {
			perror("epoll_ctl");
			abort();
		}
#endif

	} else {
		if (errno != EAGAIN) {
			fprintf(stderr, "mtcp_accept() error %s\n", 
							strerror(errno));
		}
	}

	return c;
}
/*----------------------------------------------------------------------------*/
struct thread_context *
InitializeServerThread(int core)
{
	struct thread_context *ctx;

	/* affinitize application thread to a CPU core */
#ifndef USE_LINUX
#if HT_SUPPORT
	mtcp_core_affinitize(core + (num_cores / 2));
#else
	mtcp_core_affinitize(core);
#endif /* HT_SUPPORT */
#endif

	ctx = (struct thread_context *)calloc(1, sizeof(struct thread_context));
	if (!ctx) {
		fprintf(stderr, "Failed to create thread context!\n");
		return NULL;
	}

	/* create mtcp context: this will spawn an mtcp thread */
#ifndef USE_LINUX
	ctx->mctx = mtcp_create_context(core);
	if (!ctx->mctx) {
		fprintf(stderr, "Failed to create mtcp context!\n");
		free(ctx);
		return NULL;
	}

	/* create epoll descriptor */
	ctx->ep = mtcp_epoll_create(ctx->mctx, MAX_EVENTS);
	if (ctx->ep < 0) {
		mtcp_destroy_context(ctx->mctx);
		free(ctx);
		fprintf(stderr, "Failed to create epoll descriptor!\n");
		return NULL;
	}
#else
	ctx->ep = epoll_create(MAX_EVENTS);
	if (!ctx->ep) {
		perror("epoll_create");
		free(ctx);
		return NULL;
	}
#endif

	/* allocate memory for server variables */
	ctx->svars = (struct server_vars *)
		calloc(MAX_FLOW_NUM, sizeof(struct server_vars));
	if (!ctx->svars) {
#ifndef USE_LINUX
		mtcp_close(ctx->mctx, ctx->ep);
		mtcp_destroy_context(ctx->mctx);
#else
		close(ctx->ep);
#endif
		free(ctx);
		fprintf(stderr, "Failed to create server_vars struct!\n");
		return NULL;
	}

	ctx->ssl_ctx_map = hashmap_create((unsigned int (*)(void *)) hashmap_default_int_hasher,
												 (int (*)(void *, void *)) hashmap_default_int_equals);

	return ctx;
}
/*----------------------------------------------------------------------------*/
int 
CreateListeningSocket(struct thread_context *ctx)
{
	int listener;
	int ret;

	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(PORT);

	/* create socket, set it as nonblocking, and bind to it */
#ifndef USE_LINUX
	listener = mtcp_socket(ctx->mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		fprintf(stderr, "Failed to create listening socket!\n");
		return -1;
	}
	ret = mtcp_setsock_nonblock(ctx->mctx, listener);
	if (ret < 0) {
		fprintf(stderr, "Failed to set socket in nonblocking mode.\n");
		return -1;
	}

	ret = mtcp_bind(ctx->mctx, listener, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		fprintf(stderr, "Failed to bind to the listening socket!\n");	 
		return -1;
	}
#else
	pthread_mutex_lock(&startup_lock);
	if (linux_listener == -1) {
		linux_listener = socket(AF_INET, SOCK_STREAM, 0);
		if (linux_listener < 0) {
			fprintf(stderr, "Failed to create listening socket!\n");
			return -1;
		}
		ret = bind(linux_listener, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
		if (ret < 0) {
			perror("bind");
			return -1;
		}
		if (set_nonblocking(linux_listener) < 0) {
			abort();
		}
	}
	pthread_mutex_unlock(&startup_lock);
	listener = linux_listener;
#endif

	/* listen (backlog: can be configured) */
#ifndef USE_LINUX
	ret = mtcp_listen(ctx->mctx, listener, backlog);
#else
	ret = listen(listener, backlog);
#endif
	if (ret < 0) {
		fprintf(stderr, "mtcp_listen() failed!\n");
		return -1;
	}
	
	/* wait for incoming accept events */
#ifndef USE_LINUX
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, listener, &ev);
#else
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = listener;
	if (epoll_ctl(ctx->ep, EPOLL_CTL_ADD, listener, &ev) == -1) {
		perror("epoll_ctl");
		abort();
	}
#endif
	
	return listener;
}
/*----------------------------------------------------------------------------*/
SSL_CTX *
CreateSSLContext()
{
	const SSL_METHOD *method = SSLv23_server_method();

	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return ctx;
}
/*----------------------------------------------------------------------------*/
void *
RunServerThread(void *arg)
{
	int core = *(int *)arg;
#ifndef USE_LINUX
	SSL_CTX *ssl_ctx = create_ssl_context(g_mctx);
#else
	SSL_CTX *ssl_ctx = create_ssl_context();
#endif
	configure_ssl_context(ssl_ctx);
	
	/* initialization */
	struct thread_context *ctx = InitializeServerThread(core);
	if (!ctx) {
		fprintf(stderr, "Failed to initialize server thread.\n");
		return NULL;
	}
#ifndef USE_LINUX
	mctx_t mctx = ctx->mctx;
	g_mctx[sched_getcpu()] = mctx;
#endif
	int ep = ctx->ep;

#ifndef USE_LINUX
	struct mtcp_epoll_event *events = (struct mtcp_epoll_event *)
		calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
#else
	struct epoll_event *events = (struct epoll_event *)
		calloc(MAX_EVENTS, sizeof(struct epoll_event));
#endif
	if (!events) {
		fprintf(stderr, "Failed to create event struct!\n");
		exit(-1);
	}

	int listener = CreateListeningSocket(ctx);
	if (listener < 0) {
		fprintf(stderr, "Failed to create listening socket.\n");
		exit(-1);
	}

	while (!done[core]) {
#ifndef USE_LINUX
		int nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);
#else
		int nevents = epoll_wait(ep, events, MAX_EVENTS, -1);
#endif
		if (nevents < 0) {
			if (errno != EINTR)
				perror("epoll_wait");
			break;
		}

#ifndef USE_LINUX
		int epollerr = MTCP_EPOLLERR;
		int epollout = MTCP_EPOLLOUT;
		int epollin  = MTCP_EPOLLIN;
#else
		int epollerr = EPOLLERR;
		int epollout = EPOLLOUT;
		int epollin  = EPOLLIN;
#endif
		int do_accept = FALSE;
		for (int i = 0; i < nevents; i++) {

#ifndef USE_LINUX
			int efd = events[i].data.sockid;
#else
			int efd = events[i].data.fd;
#endif
			
			if (efd == listener) {
				/* if the event is for the listener, accept connection */
				do_accept = TRUE;
				
			} else if (events[i].events & epollerr) {
				fprintf(stderr, "[CPU %d] EPOLLER event occurred on socket %d\n", core, efd);

				int err;
				socklen_t len = sizeof(err);

				/* error on the connection */
				fprintf(stderr, "[CPU %d] Error on socket %d\n", core, efd);
#ifndef USE_LINUX
				if (mtcp_getsockopt(mctx, efd, SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0) {
#else
				if (getsockopt(efd, SOL_SOCKET, SO_ERROR, (void *)&err, &len) == 0) {
#endif
					if (err != ETIMEDOUT) {
						fprintf(stderr, "Error on socket %d: %s\n", efd, strerror(err));
			 	  }
				} else {
					perror("mtcp_getsockopt");
				}
				CloseConnection(ctx, efd, &ctx->svars[efd]);

			} else if (events[i].events & epollin) {

				fprintf(stderr, "[CPU %d] EPOLLIN event occurred on socket %d\n", core, efd);
				
				int ret = HandleReadEvent(ctx, ssl_ctx, efd, &ctx->svars[efd]);
				
				if (ret == 0) {
					/* connection closed by remote host */
					CloseConnection(ctx, efd, &ctx->svars[efd]);
				} else if (ret < 0) {
					/* if not EAGAIN, it's an error */
					if (errno != EAGAIN) {
						CloseConnection(ctx, efd, &ctx->svars[efd]);
					}
				}

			} else if (events[i].events & epollout) {

				fprintf(stderr, "[CPU %d] EPOLLOUT event occurred on socket %d\n", core, efd);
				
				struct server_vars *sv = &ctx->svars[efd];
				if (sv->rspheader_sent) {
					SendUntilAvailable(ctx, efd, sv);
				} else {
					fprintf(stderr, "Socket %d: Response header not sent yet.\n", efd);
				}

			} else {
				assert(0);
			}
		}

		/* if do_accept flag is set, accept connections */
		if (do_accept) {
			while (1) {
				fprintf(stderr, "[CPU %d] Accepting connection\n", core);
				int ret = AcceptConnection(ctx, ssl_ctx, listener);
				if (ret < 0)
					break;
			}
		}

	}

	/* destroy mtcp context: this will kill the mtcp thread */
#ifndef USE_LINUX
	mtcp_destroy_context(mctx);
#endif
	pthread_exit(NULL);

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
SignalHandler(int signum)
{
	int i;

	for (i = 0; i < core_limit; i++) {
		if (app_thread[i] == pthread_self()) {
			TRACE_INFO("Server thread %d got SIGINT\n", i);
			done[i] = TRUE;
		} else {
			if (!done[i]) {
				pthread_kill(app_thread[i], signum);
			}
		}
	}
}
/*----------------------------------------------------------------------------*/
static void
printHelp(const char *prog_name)
{
	TRACE_CONFIG("%s -p <path_to_www/> -f <mtcp_conf_file> "
					 "[-N num_cores] [-c <per-process core_id>] [-h]\n",
					 prog_name);
	exit(EXIT_SUCCESS);
}
/*----------------------------------------------------------------------------*/
int 
main(int argc, char **argv)
{
	DIR *dir;
	struct dirent *ent;
	int fd;
	int ret;
	uint64_t total_read;
	int cores[MAX_CPUS];
	int process_cpu;
	int i, o;

#ifndef USE_LINUX
	struct mtcp_conf mcfg;
#endif

	num_cores = GetNumCPUs();
	core_limit = num_cores;
	process_cpu = -1;
	dir = NULL;

	if (argc < 2) {
		TRACE_CONFIG("$%s directory_to_service\n", argv[0]);
		return FALSE;
	}

	while (-1 != (o = getopt(argc, argv, "N:f:p:c:b:h:l"))) {
		switch (o) {
		case 'p':
			/* open the directory to serve */
			www_main = optarg;
			dir = opendir(www_main);
			if (!dir) {
				TRACE_CONFIG("Failed to open %s.\n", www_main);
				perror("opendir");
				return FALSE;
			}
			break;
		case 'N':
			core_limit = mystrtol(optarg, 10);
			if (core_limit > num_cores) {
				TRACE_CONFIG("CPU limit should be smaller than the "
								 "number of CPUs: %d\n", num_cores);
				return FALSE;
			}
			/** 
			 * it is important that core limit is set 
			 * before mtcp_init() is called. You can
			 * not set core_limit after mtcp_init()
			 */
#ifndef USE_LINUX
			mtcp_getconf(&mcfg);
			mcfg.num_cores = core_limit;
			mtcp_setconf(&mcfg);
#endif
			break;
		case 'f':
			conf_file = optarg;
			break;
		case 'c':
			process_cpu = mystrtol(optarg, 10);
			if (process_cpu > core_limit) {
				TRACE_CONFIG("Starting CPU is way off limits!\n");
				return FALSE;
			}
			break;
		case 'b':
			backlog = mystrtol(optarg, 10);
			break;
		case 'h':
			printHelp(argv[0]);
			break;
		case 'l':
			use_lock = 1;
			break;
		}
	}
	
	if (dir == NULL) {
		TRACE_CONFIG("You did not pass a valid www_path!\n");
		exit(EXIT_FAILURE);
	}

	nfiles = 0;
	while ((ent = readdir(dir)) != NULL) {
		if (strcmp(ent->d_name, ".") == 0)
			continue;
		else if (strcmp(ent->d_name, "..") == 0)
			continue;

		snprintf(fcache[nfiles].name, NAME_LIMIT, "%s", ent->d_name);
		snprintf(fcache[nfiles].fullname, FULLNAME_LIMIT, "%s/%s",
					www_main, ent->d_name);
		fd = open(fcache[nfiles].fullname, O_RDONLY);
		if (fd < 0) {
			perror("open");
			continue;
		} else {
			fcache[nfiles].size = lseek64(fd, 0, SEEK_END);
			lseek64(fd, 0, SEEK_SET);
		}

		fcache[nfiles].file = (char *)malloc(fcache[nfiles].size);
		if (!fcache[nfiles].file) {
			TRACE_CONFIG("Failed to allocate memory for file %s\n", 
							 fcache[nfiles].name);
			perror("malloc");
			continue;
		}

		TRACE_INFO("Reading %s (%lu bytes)\n", 
					  fcache[nfiles].name, fcache[nfiles].size);
		total_read = 0;
		while (1) {
			ret = read(fd, fcache[nfiles].file + total_read, 
						  fcache[nfiles].size - total_read);
			if (ret < 0) {
				break;
			} else if (ret == 0) {
				break;
			}
			total_read += ret;
		}
		if (total_read < fcache[nfiles].size) {
			free(fcache[nfiles].file);
			continue;
		}
		close(fd);
		nfiles++;

		if (nfiles >= MAX_FILES)
			break;
	}

	finished = 0;

	/* initialize mtcp */
#ifndef USE_LINUX
	if (conf_file == NULL) {
		TRACE_CONFIG("You forgot to pass the mTCP startup config file!\n");
		exit(EXIT_FAILURE);
	}

	ret = mtcp_init(conf_file);
	if (ret) {
		TRACE_CONFIG("Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}

	mtcp_getconf(&mcfg);
	if (backlog > mcfg.max_concurrency) {
		TRACE_CONFIG("backlog can not be set larger than CONFIG.max_concurrency\n");
		return FALSE;
	}
	
	/* register signal handler to mtcp */	
	mtcp_register_signal(SIGINT, SignalHandler);
#endif

	/* if backlog is not specified, set it to 4K */
	if (backlog == -1) {
		backlog = 4096;
	}

	init_openssl(use_lock, CRYPTO_num_locks());

	TRACE_INFO("Application initialization finished.\n");

	if (core_limit > 1) {
		for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
			cores[i] = i;
			done[i] = FALSE;
			
			if (pthread_create(&app_thread[i], 
									 NULL, RunServerThread, (void *)&cores[i])) {
				perror("pthread_create");
				TRACE_CONFIG("Failed to create server thread.\n");
				abort();
			}
			if (process_cpu != -1)
				break;
		}
		
		for (i = ((process_cpu == -1) ? 0 : process_cpu); i < core_limit; i++) {
			pthread_join(app_thread[i], NULL);
			
			if (process_cpu != -1)
				break;
		}
	} else {
		i = (process_cpu == -1) ? 0 : process_cpu;
		cores[0] = 0;
		done[0] = FALSE;
		RunServerThread((void *) &cores[0]);
	}

	cleanup_openssl(use_lock, CRYPTO_num_locks());
#ifndef USE_LINUX
	mtcp_destroy();
#endif
	closedir(dir);
	return 0;
}
