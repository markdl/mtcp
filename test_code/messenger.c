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
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ssl_functions.h>
#endif

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
#define FD_OVERHEAD_FACTOR 3
#define MAX_EVENTS_FACTOR 3 // Not sure if these values are related
/*----------------------------------------------------------------------------*/
#ifndef USE_LINUX

#define FUNC_NAME_CONCAT(x, y) x ## y
#define GET_SOCKET_FUNC(func) FUNC_NAME_CONCAT(mtcp_, func)

#define SOCKET_FUNC(func, core, ...) GET_SOCKET_FUNC(func)(contexts[core].mctx, \
																			  __VA_ARGS__)
#define IS_EVENT_TYPE(event, type) event & MTCP_ ## type
#define GET_SOCKET_FUNC_NAME(func) "mtcp_" #func

#else

#define SOCKET_FUNC(func, core, ...) func(__VA_ARGS__)
#define IS_EVENT_TYPE(event, type) event & type
#define GET_SOCKET_FUNC_NAME(func) #func

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

	int ep;
	uint64_t connects;
	uint64_t msgs_sent;
	uint64_t bytes_sent;
	
	struct connection *connections;
};
/*----------------------------------------------------------------------------*/
static int port = 8080;
static int backlog = 4096;
static int sndbuf_size = 8192; // Default for Linux
static int max_fds = 65000;    // Default for Linux
static char *msg = NULL;
static int msgs_per_conn = 0;
static int payload_size;
static int core_limit;
static pthread_t main_thread;
static int cores[MAX_CPUS];
static pthread_t app_thread[MAX_CPUS];
static struct thread_context contexts[MAX_CPUS];
/*----------------------------------------------------------------------------*/
#ifndef USE_LINUX
static mctx_t g_mctx[MAX_CPUS];
static char *conf_file = "mtcp.conf";
#else
static pthread_mutex_t startup_lock;
static int linux_listener = -1;
#endif
/*----------------------------------------------------------------------------*/
#ifdef USE_SSL
SSL_CTX *ssl_ctx;
int use_global_lock = FALSE;
#endif
/*----------------------------------------------------------------------------*/
void
print_interval_stats(struct thread_context *ctx, int core,
							struct timeval start, struct timeval end)
{
	double seconds = (end.tv_sec - start.tv_sec) +
		((end.tv_usec - start.tv_usec) / 1000000.0);
	double tp = 0;
	if (ctx->bytes_sent > 0)
		tp = (ctx->bytes_sent * 8.0) / 1024 / 1024 / 1024;
	printf("[CPU %d] Interval stats - M/s: %.2f, Tp: %.2f Gbps, Cnx/s: %.2f\n",
			 core, ctx->msgs_sent / seconds, tp / seconds,
			 ctx->connects / seconds);
	ctx->msgs_sent = 0;
	ctx->bytes_sent = 0;
	ctx->connects = 0;
	fflush(stdout);
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
int
init_server_thread(int core, struct thread_context *ctx) {
#ifndef USE_LINUX
	mtcp_core_affinitize(core);

	ctx->mctx = mtcp_create_context(core);
	if (ctx->mctx == NULL) {
		fprintf(stderr, "Failed to create mtcp context\n");
		return -1;
	}
	g_mctx[core] = ctx->mctx;
#endif

	ctx->ep = SOCKET_FUNC(epoll_create, core, max_fds * MAX_EVENTS_FACTOR);
	if (ctx->ep < 0) {
		perror(GET_SOCKET_FUNC_NAME(epoll_create));
		fprintf(stderr, "Failed to create epoll with %d events\n", max_fds * MAX_EVENTS_FACTOR);
#ifndef USE_LINUX
		mtcp_destroy_context(ctx->mctx);
#endif
		return -1;
	}
	
	ctx->connections = (struct connection *)
		calloc(max_fds * FD_OVERHEAD_FACTOR * core_limit,
				 sizeof(struct connection));
	if (ctx->connections == NULL) {
		perror("connections calloc");
		SOCKET_FUNC(close, core, ctx->ep);
#ifndef USE_LINUX
		mtcp_destroy_context(ctx->mctx);
#endif
		return -1;
	}
	
	return 1;
}
/*----------------------------------------------------------------------------*/
int
create_listening_socket(int core, struct thread_context *ctx)
{
	int listener;
	int ret;
	int create_socket = TRUE;
	
#ifdef USE_LINUX
	pthread_mutex_lock(&startup_lock);
	if (linux_listener != -1) {
		pthread_mutex_unlock(&startup_lock);
		listener = linux_listener;
		create_socket = FALSE;
	}
#endif

	if (create_socket) {
		listener = SOCKET_FUNC(socket, core, AF_INET, SOCK_STREAM, 0);
		if (listener < 0) {
			perror(GET_SOCKET_FUNC_NAME(socket));
			listener = -1;
		} else {

			ret = SOCKET_FUNC(setsock_nonblock, core, listener);
			if (ret < 0) {
				fprintf(stderr, "Failed setting socket to nonblocking\n");
				listener = -1;
			} else {

#ifdef USE_LINUX
				if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 },
									sizeof(int)) < 0)
					perror("setsockopt REUSEADDR");
				if (setsockopt(listener, SOL_SOCKET, SO_REUSEPORT, &(int){ 1 },
									sizeof(int)) < 0)
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
					perror(GET_SOCKET_FUNC_NAME(bind));
				listener = -1;
				}
			}
		}
	}
	
#ifdef USE_LINUX
	if (create_socket) {
		linux_listener = listener;
		pthread_mutex_unlock(&startup_lock);
	}
#endif

	if (listener < 0)
		return listener;

	ret = SOCKET_FUNC(listen, core, listener, backlog);
	if (ret < 0) {
		perror(GET_SOCKET_FUNC_NAME(listen));
		fprintf(stderr, "[CPU %d] Listen failed. Listener: %d, backlog: %d\n",
				  core, listener, backlog);
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
		perror(GET_SOCKET_FUNC_NAME(epoll_ctl));
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
	SSL_free(conn.ssl);
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
		int len = MIN(sndbuf_size, payload_size - conn->msg_pos);
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

#ifndef USE_LINUX
		if (c >= max_fds * FD_OVERHEAD_FACTOR * core_limit) {
			fprintf(stderr, "Invalid socket id %d\n", c);
			return -1;
		}
#endif

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
			perror(GET_SOCKET_FUNC_NAME(epoll_ctl));
			abort();
		}
		
	} else {
		if (errno != EAGAIN) {
			perror(GET_SOCKET_FUNC_NAME(accept));
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
		conn.ssl = ssl_new_connection(ssl_ctx, sockid);
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
		perror(GET_SOCKET_FUNC_NAME(epoll_ctl));
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
		calloc(max_fds * MAX_EVENTS_FACTOR, sizeof(struct mtcp_epoll_event));
#else
	struct epoll_event *events = (struct epoll_event *)
		calloc(max_fds * MAX_EVENTS_FACTOR, sizeof(struct epoll_event));
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
			print_interval_stats(ctx, core, prev_tv, curr_tv);
			prev_tv = curr_tv;
		}
		
		int nevents = SOCKET_FUNC(epoll_wait, core, ctx->ep, events,
										  max_fds * MAX_EVENTS_FACTOR, -1);
		if (nevents < 0) {
			if (errno != EINTR)
				perror(GET_SOCKET_FUNC_NAME(epoll_wait));
			break;
		}

		int do_accept = FALSE;

		for (int i = 0; i < nevents; i++) {
			
			if (i % 100 == 0) {
				gettimeofday(&curr_tv, NULL);
				if (curr_tv.tv_sec > prev_tv.tv_sec && curr_tv.tv_usec > prev_tv.tv_usec) {
					print_interval_stats(ctx, core, prev_tv, curr_tv);
					prev_tv = curr_tv;
				}
			}

			
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
					perror(GET_SOCKET_FUNC_NAME(getsockopt));
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
	while (-1 != (o = getopt(argc, argv, "N:f:c:b:s:k:p:lh"))) {
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
			break;
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
	sndbuf_size = mcfg.sndbuf_size;
	max_fds = mcfg.max_concurrency / core_limit;

	mtcp_register_signal(SIGINT, signal_handler);
#endif

#ifdef USE_SSL
	init_openssl(use_global_lock, CRYPTO_num_locks());

#ifndef USE_LINUX
	ssl_ctx = create_ssl_context(g_mctx);
#else
	ssl_ctx = create_ssl_context();
#endif
	configure_ssl_context(ssl_ctx);

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
	cleanup_openssl(use_global_lock, CRYPTO_num_locks());
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
