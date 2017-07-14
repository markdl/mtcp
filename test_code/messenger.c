/*
 * Accept incoming connections from clients. If -s and -k values given, send k
 * messages of s bytes to the client, or 1 payload if s is set and k is not. If
 * no -s given, close connection immediately after accepting.
 */

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

/*----------------------------------------------------------------------------*/
#define MAX_CPUS 32
#define MAX_FLOW_NUM 65535
#define MAX_EVENTS (MAX_FLOW_NUM * 3)
#define SNDBUF_SIZE (8*1024)
/*----------------------------------------------------------------------------*/
#ifndef USE_LINUX

#define FUNC_NAME_CONCAT(x, y) x ## y
#define FUNC_NAME_CONCAT_HELPER(x, y) FUNC_NAME_CONCAT(x, y)
#define SOCKET_FUNC(func, core, ...) FUNC_NAME_CONCAT_HELPER(mtcp_, func)(contexts[core].mctx, __VA_ARGS__)
#define IS_EVENT_TYPE(event, type) event & MTCP_ ## type

#else

#define SOCKET_FUNC(func, core, ...) func(__VA_ARGS__)
#define IS_EVENT_TYPE(event, type) event & type

#endif
/*----------------------------------------------------------------------------*/
struct connection {
	int msgs_sent;
	int msg_pos;

#ifdef USE_SSL
	int accepted;
	SSL *ssl;
#endif
};
/*----------------------------------------------------------------------------*/
struct thread_context {

#ifndef USE_LINUX
	mctx_t mctx;
#endif

#ifdef USE_SSL
	SSL_CTX *ssl_ctx;
#endif

	int ep;
	uint64_t connects;
	uint64_t msgs_sent;
	uint64_t bytes_sent;
	
	struct connection *connections;
};
/*----------------------------------------------------------------------------*/
static int port = 8080;
static int backlog = 4096;
static char *msg = NULL;
static int msgs_per_conn = 0;
static int payload_size;
static int cores[MAX_CPUS];
static int core_limit;
static pthread_t app_thread[MAX_CPUS];
static struct thread_context contexts[MAX_CPUS];
static pthread_t main_thread;
/*----------------------------------------------------------------------------*/
#ifdef USE_LINUX

static pthread_mutex_t startup_lock;
static int linux_listener = -1;

#else

static char *conf_file = "mtcp.conf";

#endif

#ifdef USE_SSL
int use_global_lock = FALSE;
static pthread_mutex_t *locks;
#endif
/*----------------------------------------------------------------------------*/
void
print_interval_stats(struct thread_context *ctx, int core)
{
	double tp = (ctx->bytes_sent * 8.0) / 1024 / 1024 / 1024;
	fprintf(stderr, "[CPU %d] Interval stats - M/s: %lu, Tp: %.2f Gbps, "
			  "Cnx/s: %lu\n", core, ctx->msgs_sent, tp, ctx->connects);
	ctx->msgs_sent = 0;
	ctx->bytes_sent = 0;
	ctx->connects = 0;
}
/*----------------------------------------------------------------------------*/
int
setsock_nonblock(int fd)
{
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
#ifdef USE_SSL
void
thread_locking(int mode, int n, const char* file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&locks[n]);
	else
		pthread_mutex_unlock(&locks[n]);
}
/*----------------------------------------------------------------------------*/
unsigned long
thread_id()
{
	return (unsigned long) pthread_self();
}
/*----------------------------------------------------------------------------*/
void
thread_setup()
{
	if (use_global_lock) {
		locks = (pthread_mutex_t *) calloc(CRYPTO_num_locks(), sizeof(pthread_mutex_t));
		if (!locks) {
			perror("locks calloc");
			abort();
		}
		for (int i = 0; i < CRYPTO_num_locks(); i++) {
			if (pthread_mutex_init(&locks[i], NULL) != 0) {
				perror("pthread_mutex_init");
				abort();
			}
		}

		CRYPTO_set_id_callback(thread_id);
		CRYPTO_set_locking_callback(thread_locking);
	}
}
/*----------------------------------------------------------------------------*/
void
thread_cleanup()
{
	if (use_global_lock) {
		for (int i = 0; i < CRYPTO_num_locks(); i++) {
			pthread_mutex_destroy(&locks[i]);
		}
		free(locks);
		
		CRYPTO_set_id_callback(NULL);
		CRYPTO_set_locking_callback(NULL);
	}
}
/*----------------------------------------------------------------------------*/
void
init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	thread_setup();
}
/*----------------------------------------------------------------------------*/
void
cleanup_openssl()
{
	thread_cleanup();
	EVP_cleanup();
}
/*----------------------------------------------------------------------------*/
SSL_CTX *
create_ssl_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	
	method = SSLv23_server_method();
	
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		abort();
	}
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	
	return ctx;
}
/*----------------------------------------------------------------------------*/
void
configure_ssl_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);
	
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "credentials/cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	if (SSL_CTX_use_PrivateKey_file(ctx, "credentials/key.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}
/*----------------------------------------------------------------------------*/
static int
my_sock_read(BIO *b, char *out, int outl)
{
	int ret;
	if (out != NULL) {
#ifndef USE_LINUX
		int core = sched_getcpu();
#endif
		errno = 0;
		ret = SOCKET_FUNC(read, core, b->num, out, outl);
		BIO_clear_retry_flags(b);
		if (ret <= 0) {
			if (BIO_sock_should_retry(ret))
				BIO_set_retry_read(b);
		}
	}
	return (ret);
}
/*----------------------------------------------------------------------------*/
static int
my_sock_write(BIO *b, const char *in, int inl)
{
#ifndef USE_LINUX
	int core = sched_getcpu();
#endif
	errno = 0;

	int ret = SOCKET_FUNC(write, core, b->num, in, inl);
	BIO_clear_retry_flags(b);
	if (ret <= 0) {
		if (BIO_sock_should_retry(ret))
			BIO_set_retry_write(b);
	}
	return (ret);
}
#endif // #ifdef USE_SSL
/*----------------------------------------------------------------------------*/
int
init_server_thread(int core, struct thread_context *ctx) {
#ifndef USE_LINUX
	mtcp_core_affinitize(core);

	ctx->mctx = mtcp_create_context(core);
	if (ctx->mctx == NULL) {
		fprintf(stderr, "Failed to create mtcp context\n");
		return -1;
	}
#endif

	ctx->ep = SOCKET_FUNC(epoll_create, core, MAX_EVENTS);
	if (ctx->ep < 0) {
		perror("epoll_create");
#ifndef USE_LINUX
		mtcp_destroy_context(ctx->mctx);
#endif
		return -1;
	}
	
	ctx->connections = (struct connection *) calloc(MAX_FLOW_NUM,
																	sizeof(struct connection));
	if (ctx->connections == NULL) {
		perror("connections calloc");
		SOCKET_FUNC(close, core, ctx->ep);
#ifndef USE_LINUX
		mtcp_destroy_context(ctx->mctx);
#endif
		return -1;
	}
	
#ifdef USE_SSL
	ctx->ssl_ctx = create_ssl_context();
	configure_ssl_context(ctx->ssl_ctx);
#endif

	return 1;
}
/*----------------------------------------------------------------------------*/
int
create_listening_socket(int core, struct thread_context *ctx)
{
	int listener;
	int ret;
	
#ifdef USE_LINUX
	pthread_mutex_lock(&startup_lock);
	if (linux_listener == -1)
#endif

	{
		listener = SOCKET_FUNC(socket, core, AF_INET, SOCK_STREAM, 0);
		if (listener < 0) {
			perror("socket");
			listener = -1;
		}

		ret = SOCKET_FUNC(setsock_nonblock, core, listener);
		if (ret < 0) {
			fprintf(stderr, "Failed setting socket to nonblocking\n");
			listener = -1;
		}

#ifdef USE_LINUX
		if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
			perror("setsockopt REUSEADDR");
		if (setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 }, sizeof(int)) < 0)
			perror("setsockopt REUSEPORT");
#endif
		
		struct sockaddr_in saddr;
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = INADDR_ANY;
		saddr.sin_port = htons(port);

		ret = SOCKET_FUNC(bind, core, listener,
								(struct sockaddr *) &saddr,
								sizeof(struct sockaddr_in));
		if (ret < 0) {
			perror("bind");
			listener = -1;
		}

	}
	
#ifdef USE_LINUX
	pthread_mutex_unlock(&startup_lock);
	linux_listener = listener;
#endif

	if (listener < 0)
		return listener;

	ret = SOCKET_FUNC(listen, core, listener, backlog);
	if (ret < 0) {
		perror("listen");
		return -1;
	}

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
void
close_connection(struct thread_context *ctx, int core, int sockid)
{
#ifndef USE_LINUX
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
#else
	epoll_ctl(ctx->ep, EPOLL_CTL_DEL, sockid, NULL);
#endif
	
#ifdef USE_SSL
	struct connection conn = ctx->connections[sockid];
	SSL_free(conn.
				ssl);
#endif

	SOCKET_FUNC(close, core, sockid);
}
/*----------------------------------------------------------------------------*/
int
send_messages(struct thread_context *ctx, int core, int sockid)
{
	struct connection *conn = &ctx->connections[sockid];

	int sent = 0;
	int ret = 1;
	while (conn->msgs_sent < msgs_per_conn && ret > 0) {
		int len = MIN(SNDBUF_SIZE, payload_size - conn->msg_pos);
		if (len <= 0) {
			break;
		}
		
#ifndef USE_SSL
		ret = SOCKET_FUNC(write, core, sockid, msg + conn->msg_pos, len);
#else
		ret = SSL_write(conn->ssl, msg + conn->msg_pos, len);
#endif
		
		if (ret < 0) {
			if (errno != EAGAIN) {
				fprintf(stderr, "[CPU %d] Failed to write to socket %d\n",
						  core, sockid);
			}
			break;
		}
		
		if (ret == len) {
			conn->msg_pos = 0;
			conn->msgs_sent++;
			ctx->msgs_sent++;
			} else {
			conn->msg_pos += ret;
		}
		sent += ret;
		ctx->bytes_sent += ret;
	}

	if (conn->msgs_sent == msgs_per_conn) {
		close_connection(ctx, core, sockid);
	}

	return sent;
}
/*----------------------------------------------------------------------------*/
void
clean_connection(struct connection *conn)
{
	conn->msgs_sent = 0;
	conn->msg_pos = 0;

#ifdef USE_SSL
	conn->accepted = 0;
	conn->ssl = NULL;
#endif
}
/*----------------------------------------------------------------------------*/
int
accept_connection(struct thread_context *ctx, int core, int listener)
{
	int c = SOCKET_FUNC(accept, core, listener, NULL, NULL);
	if (c >= 0) {

		if (c >= MAX_FLOW_NUM) {
			fprintf(stderr, "Invalid socket id %d\n", c);
			return -1;
		}

		struct connection *conn = &ctx->connections[c];
		clean_connection(conn);

		int ret = SOCKET_FUNC(setsock_nonblock, core, c);
		if (ret < 0) {
			fprintf(stderr, "Failed to set accepted connection to non-blocking\n");
			abort();
		}

#ifndef USE_LINUX
		struct mtcp_epoll_event ev;
		ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
		ev.data.sockid = c;
		ret = mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, c, &ev);
#else
		struct epoll_event ev;
		ev.events = EPOLLIN | EPOLLET | EPOLLOUT;
		ev.data.fd = c;
		ret = epoll_ctl(ctx->ep, EPOLL_CTL_ADD, c, &ev);
#endif
		if (ret < 0) {
			perror("epoll_ctl");
			abort();
		}
		
	} else {
		if (errno != EAGAIN) {
			perror("accept");
		}
		return c;
	}

	ctx->connects++;
	
	return 1;
}
/*----------------------------------------------------------------------------*/
int
handle_read_event(struct thread_context *ctx, int core, int sockid)
{
	// Read event should only occur if doing SSL handshake
#ifndef USE_SSL
	fprintf(stderr, "SSL is not enabled\n");
	return -1;
#else
	struct connection conn = ctx->connections[sockid];
	if (conn.ssl == NULL) {
		conn.accepted = 0;
		conn.ssl = SSL_new(ctx->ssl_ctx);
		SSL_set_fd(conn.ssl, sockid);
		BIO *wbio = SSL_get_wbio(conn.ssl);
		BIO *rbio = SSL_get_rbio(conn.ssl);
		wbio->method->bwrite = my_sock_write;
		rbio->method->bread = my_sock_read;
		BIO_set_nbio(wbio, 1);
		BIO_set_nbio(rbio, 1);
		SSL_set_bio(conn.ssl, rbio, wbio);
	}
	
	if (!conn.accepted) {
		int rd = SSL_accept(conn.ssl);
		if (rd <= 0) {
			int err = SSL_get_error(conn.ssl, rd);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				return 1;
			}
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "Socket %d: SSL handshake failed\n", sockid);
			return -2;
		}
		conn.accepted = 1;
	} else {
		fprintf(stderr, "[CPU %d] Socket %d has read event after SSL handshake\n",
				  core, sockid);
		return -3;
	}

#ifndef USE_LINUX
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLIN | MTCP_EPOLLOUT;
	ev.data.sockid = sockid;
   int ret = mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_MOD, sockid, &ev);
#else
	struct epoll_event ev;
	ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
	ev.data.fd = sockid;
	int ret = epoll_ctl(ctx->ep, EPOLL_CTL_MOD, sockid, &ev);
#endif
	if (ret < 0) {
		perror("epoll_ctl");
		abort();
	}

	send_messages(ctx, core, sockid);

	return 1;
#endif
}
/*----------------------------------------------------------------------------*/
void *
run_server_thread(void *args)
{
	int core = *(int *) args;
	struct thread_context *ctx = &contexts[core];
	if (init_server_thread(core, ctx) < 0) {
		fprintf(stderr, "[CPU %d] Failed to initialize thread context\n", core);
		exit(EXIT_FAILURE);
	}

#ifndef USE_LINUX
	struct mtcp_epoll_event *events = (struct mtcp_epoll_event *)
		calloc(MAX_EVENTS, sizeof(struct mtcp_epoll_event));
#else
	struct epoll_event *events = (struct epoll_event *)
		calloc(MAX_EVENTS, sizeof(struct epoll_event));
#endif
	if (!events) {
		fprintf(stderr, "Failed to create events struct\n");
		exit(EXIT_FAILURE);
	}

	int listener = create_listening_socket(core, ctx);
	if (listener < 0) {
		fprintf(stderr, "Failed to create listening socket.\n");
		exit(EXIT_FAILURE);
	}

	struct timeval curr_tv, prev_tv;
	gettimeofday(&prev_tv, NULL);

	while (1) {

	   gettimeofday(&curr_tv, NULL);
		if (curr_tv.tv_sec > prev_tv.tv_sec && curr_tv.tv_usec > prev_tv.tv_usec) {
			print_interval_stats(ctx, core);
			prev_tv = curr_tv;
		}
		
		int nevents = SOCKET_FUNC(epoll_wait, core, ctx->ep, events,
										  MAX_EVENTS, -1);
		if (nevents < 0) {
			if (errno != EINTR)
				perror("epoll_wait");
			break;
		}

		int do_accept = FALSE;

		for (int i = 0; i < nevents; i++) {
#ifndef USE_LINUX
			int efd = events[i].data.sockid;
#else
			int efd = events[i].data.fd;
#endif

			if (efd == listener) {
				do_accept = TRUE;
			} else if (IS_EVENT_TYPE(events[i].events, EPOLLERR)) {

				int err;
				socklen_t len = sizeof(err);
				
				if (SOCKET_FUNC(getsockopt, core, efd, SOL_SOCKET, SO_ERROR,
									 (void *) &err, &len) == 0) {
					if (err != ETIMEDOUT) {
						fprintf(stderr, "[CPU %d] Error on socket %d: %s\n",
								  core, efd, strerror(err));
					}
				} else {
					perror("mtcp_getsockopt");
				}
				close_connection(ctx, core, efd);
				
			} else if (IS_EVENT_TYPE(events[i].events, EPOLLIN)) {
				
				int ret = handle_read_event(ctx, core, efd);
				if (ret == 0 || (ret < 0 && errno != EAGAIN)) {
					close_connection(ctx, core, efd);
				}
				
			} else if (IS_EVENT_TYPE(events[i].events, EPOLLOUT)) {
				
				send_messages(ctx, core, efd);
				
			}
			
		} // End of events loop

		if (do_accept) {
			while (1) {
				if (accept_connection(ctx, core, listener) < 0) {
					break;
				}
			}
		}
		
	} // end of while loop

#ifndef USE_LINUX
	mtcp_destroy_context(contexts[core].mctx);
#endif
	pthread_exit(NULL);

	return NULL;
}
/*----------------------------------------------------------------------------*/
void
signal_handler(int signum)
{
	if (pthread_self() != main_thread) {
		// If application thread, pass signal to main thread
		pthread_kill(main_thread, signum);
	} else {
		// Otherwise, kill all application threads
		for (int i = 0; i < core_limit; i++) {
			pthread_kill(app_thread[i], signum);
		}
	}
}
/*----------------------------------------------------------------------------*/
int
main(int argc, char **argv)
{
	int process_cpu = -1;
	int num_cores = GetNumCPUs();
	core_limit = num_cores;
	payload_size = -1;
	main_thread = pthread_self();
	
	int o;
	while (-1 != (o = getopt(argc, argv, "N:f:c:b:s:k:p:l:h"))) {
		switch (o) {
		case 'N': // Number of cores
			core_limit = mystrtol(optarg, 10);
			if (core_limit > num_cores) {
				fprintf(stderr, "CPU limit must be smaller than number"
						  "of CPUs: %d\n", num_cores);
				return EXIT_FAILURE;
			}
			break;
#ifndef USE_LINUX
		case 'f': // MTCP configuration file
			conf_file = optarg;
			break;
#endif
		case 'c':
			process_cpu = mystrtol(optarg, 10);
			if (process_cpu > core_limit) {
				fprintf(stderr, "Starting CPU must not be larger than core "
						  "limit\n");
				return EXIT_FAILURE;
			}
			core_limit = process_cpu; // Ensures we only spawn one thread
			break;
		case 'b':
			backlog = mystrtol(optarg, 10);
			break;
		case 's':
			payload_size = mystrtol(optarg, 10);
			if (payload_size <= 0) {
				fprintf(stderr, "Message size must be positive\n");
				return EXIT_FAILURE;
			}
			if (msgs_per_conn <= 0) {
				msgs_per_conn = 1;
			}
			break;
		case 'k':
			msgs_per_conn = mystrtol(optarg, 10);
			break;
		case 'p':
			port = mystrtol(optarg, 10);
			break;
		case 'l':
#ifdef USE_SSL
			use_global_lock = TRUE;
#else
			fprintf(stderr, "SSL is not enabled\n");
#endif
		case 'h':
			printf("Usage: %s [-f <mtcp_conf_file>] [-b backlog_size] "
					 "[-s <msg size>] [-k <msgs per connection>] "
					 "[-N num_cores] [-c <per-processs core_id>] "
					 "[-p <port>] [-h]\n", argv[0]);
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "Unrecognized option: %c\n", o);
	   }
	}

	// Generate ascii message of s characters
	if (payload_size > 0) {
		msg = (char *) calloc(payload_size + 1, sizeof(char));
		msg[payload_size] = '\0';
		int c = 65;
		for (int i = 0; i < payload_size; i++) {
			msg[i] = (char) c++;
			if (c >= 91)
				c = 65;
		}
		fprintf(stderr, "Message being sent: %s\n", msg);
	}

#ifndef USE_LINUX
	struct mtcp_conf mcfg;
	mtcp_getconf(&mcfg);
	mcfg.num_cores = core_limit;
	mtcp_setconf(&mcfg);
	int ret = mtcp_init(conf_file);
	if (ret) {
		fprintf(stderr, "Failed to initialize mtcp\n");
		return EXIT_FAILURE;
	}

	mtcp_getconf(&mcfg);
	if (backlog > mcfg.max_concurrency) {
		fprintf(stderr, "Backlog cannot be larger than CONFIG.max_concurrency\n");
		return EXIT_FAILURE;
	}

	mtcp_register_signal(SIGINT, signal_handler);
#endif

#ifdef USE_SSL
	init_openssl();
#endif

	// Spawn listener threads
	int starting_core = (process_cpu == -1) ? 0 : process_cpu;
	for (int i = starting_core; i < core_limit; i++) {
		cores[i] = i;
		
		if (pthread_create(&app_thread[i], NULL,
								 run_server_thread, (void *) &cores[i])) {
			perror("pthread_create");
			abort();
		}
	}

	for (int i = starting_core; i < core_limit; i++) {
		pthread_join(app_thread[i], NULL);
	}

#ifdef USE_SSL
	cleanup_openssl();
#endif

#ifndef USE_LINUX
	mtcp_destroy();
#else
	close(linux_listener);
#endif

	if (msg != NULL)
		free(msg);

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/
