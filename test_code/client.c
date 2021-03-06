/*
 * Continuously maintain the given max_concurrency concurrent connections
 * with the given host:port and verify the contents of the -k messages of
 * size -s received from the host.
 */

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <assert.h>
#include <limits.h>
#include <sys/time.h>
#include <sched.h>

#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ssl_functions.h>
#endif

#ifndef USE_LINUX

#include <mtcp_api.h>
#include <mtcp_epoll.h>

#else

#include <sys/epoll.h>

#endif

#include "cpu.h"
#include "rss.h"
#include "http_parsing.h"
#include "netlib.h"
#include "debug.h"

/*----------------------------------------------------------------------------*
 * FD_OVERHEAD_FACTOR was a magic number in the epwget example that I extracted
 * into this macro. I believe this is used to delay a potential race condition
 * in the client code that occurs when a new connection is created because
 * max_concurrency is not reached yet, but there are resources from a prior
 * closed connection that has not been released yet.
 *----------------------------------------------------------------------------*/
#define FD_OVERHEAD_FACTOR 6
/*----------------------------------------------------------------------------*/
#define MAX_CPUS 32
#define BUF_SIZE (8 * 1024)
#define IP_RANGE 50
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
	int msgs_rcvd;
	int msg_pos;
	int content_error;

	struct timeval t_start;
	struct timeval t_end;

#ifdef USE_SSL
	int accepted;
	SSL *ssl;
#endif
};
/*----------------------------------------------------------------------------*/
struct interval_stats {
	uint64_t connects;
	uint64_t msgs_rcvd;
	uint64_t bytes_rcvd;

	uint64_t resp_entries;
	uint64_t sum_resp_time;
	uint64_t max_resp_time;
};
/*----------------------------------------------------------------------------*/
struct thread_context {

#ifndef USE_LINUX
	mctx_t mctx;
#endif
	
	int core;
	int ep;

	uint64_t completes;
	uint64_t incompletes;
	uint64_t started;
	uint64_t pending;
	
	uint64_t timeouts;
	uint64_t errors;
	uint64_t content_errors;
	uint64_t length_errors;
	uint64_t epoll_errors;
	uint64_t read_errors;

#ifdef USE_SSL
	uint64_t handshake_errors;
#endif

	struct interval_stats stats;
	struct connection *connections;
};
/*----------------------------------------------------------------------------*/
static int max_fds;
static int core_limit;
static int concurrency;
static char *msg;
static int msg_size;
static int msgs_per_conn;
static in_addr_t daddr;
static in_port_t dport;
static in_addr_t saddr;
static pthread_t app_thread[MAX_CPUS];
static struct thread_context contexts[MAX_CPUS];
static pthread_t main_thread;

#ifdef USE_SSL
int use_global_lock = FALSE;
SSL_CTX *ssl_ctx;

#ifndef USE_LINUX
static mctx_t g_ctx[MAX_CPUS];
#endif

#endif
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
void
clean_interval_stats(struct interval_stats *stats)
{
	stats->connects = 0;
	stats->msgs_rcvd = 0;
	stats->bytes_rcvd = 0;

	stats->resp_entries = 0;
	stats->sum_resp_time = 0;
	stats->max_resp_time = 0;
}
/*----------------------------------------------------------------------------*/
void
clean_context(struct thread_context *ctx)
{
	ctx->completes = 0;
	ctx->incompletes = 0;
	ctx->started = 0;
	ctx->pending = 0;
	
	ctx->timeouts = 0;
	ctx->errors = 0;
	ctx->content_errors = 0;
	ctx->length_errors = 0;
	ctx->epoll_errors = 0;
	ctx->read_errors = 0;
	
#ifdef USE_SSL
	ctx->handshake_errors = 0;
#endif

	clean_interval_stats(&ctx->stats);
}
/*----------------------------------------------------------------------------*/
struct thread_context *
init_context(int core)
{
	struct thread_context *ctx = &contexts[core];
	ctx->core = core;
	clean_context(ctx);

#ifndef USE_LINUX
	ctx->mctx = mtcp_create_context(core);
	if (ctx->mctx == NULL) {
		fprintf(stderr, "Failed to create mtcp context\n");
		free(ctx);
		return NULL;
	}
#ifdef USE_SSL
	g_ctx[core] = ctx->mctx; // Only necessary if SSL + MTCP
#endif
#endif

	return ctx;
}
/*----------------------------------------------------------------------------*/
void
clean_connection(struct connection *conn)
{
	conn->msgs_rcvd = 0;
	conn->msg_pos = 0;
	conn->content_error = 0;

#ifdef USE_SSL
	conn->accepted = 0;
	conn->ssl = NULL;
#endif

	gettimeofday(&conn->t_start, NULL);
}
/*----------------------------------------------------------------------------*/
static inline int
create_connection(struct thread_context *ctx)
{
	int sockid = SOCKET_FUNC(socket, ctx->core, AF_INET, SOCK_STREAM, 0);
	if (sockid < 0) {
		perror("socket");
		return -1;
	}
	clean_connection(&ctx->connections[sockid]);
	int ret = SOCKET_FUNC(setsock_nonblock, ctx->core, sockid);
	if (ret < 0) {
		fprintf(stderr, "Failed to set socket to nonblocking\n");
		exit(EXIT_FAILURE);
	}

#ifdef USE_LINUX
	if (setsockopt(sockid, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0)
		perror("setsockopt REUSEADDR");

	struct linger linger;
	linger.l_onoff = 1;
	linger.l_linger = 0;
	if (setsockopt(sockid, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) < 0)
		perror("Unable to set socket linger option");
#endif

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = daddr;
	addr.sin_port = dport;

	ret = SOCKET_FUNC(connect, ctx->core, sockid, (struct sockaddr *) &addr,
							sizeof(struct sockaddr_in));
	if (ret < 0 && errno != EINPROGRESS) {
		perror("connect");
		SOCKET_FUNC(close, ctx->core, sockid);
		return -1;
	}
	ctx->started++;
	ctx->pending++;
	ctx->stats.connects++;

#ifndef USE_LINUX
	struct mtcp_epoll_event ev;
	ev.events = MTCP_EPOLLOUT | MTCP_EPOLLIN;
	ev.data.sockid = sockid;
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_ADD, sockid, &ev);
#else
	struct epoll_event ev;
	ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
	ev.data.fd = sockid;
	epoll_ctl(ctx->ep, EPOLL_CTL_ADD, sockid, &ev);
#endif

	return sockid;
}
/*----------------------------------------------------------------------------*/
static inline void
close_connection(struct thread_context *ctx, int sockid)
{
#ifndef USE_LINUX
	mtcp_epoll_ctl(ctx->mctx, ctx->ep, MTCP_EPOLL_CTL_DEL, sockid, NULL);
#else
	epoll_ctl(ctx->ep, EPOLL_CTL_DEL, sockid, NULL);
#endif

#ifdef USE_SSL
	SSL_free(ctx->connections[sockid].ssl);
#endif
	
	SOCKET_FUNC(close, ctx->core, sockid);
	ctx->pending--;
	while (ctx->pending < concurrency) {
		if (create_connection(ctx) < 0) {
			break;
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline int
download_complete(struct thread_context *ctx, int sockid,
						struct connection *conn)
{	
	if (conn->msgs_rcvd != msgs_per_conn) {
		ctx->incompletes++;
		ctx->errors++;
	} else {
		ctx->completes++;
	}

	gettimeofday(&conn->t_end, NULL);
	uint64_t tdiff = (conn->t_end.tv_sec - conn->t_start.tv_sec) * 1000000 +
		(conn->t_end.tv_usec - conn->t_start.tv_usec);
	ctx->stats.resp_entries++;
	ctx->stats.sum_resp_time += tdiff;
	if (tdiff > ctx->stats.max_resp_time)
		ctx->stats.max_resp_time = tdiff;

	close_connection(ctx, sockid);

	return 0;
}
/*----------------------------------------------------------------------------*/
static inline int
do_ssl_handshake(struct thread_context *ctx, int sockid)
{
#ifdef USE_SSL
	struct connection *conn = &ctx->connections[sockid];
		
	// Expect ssl handshake if it hasn't been done yet
	if (conn->ssl == NULL) {
		conn->accepted = 0;
		conn->ssl = ssl_new_connection(ssl_ctx, sockid);
	}
	
	if (!conn->accepted) {
		int rd = SSL_connect(conn->ssl);
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
	}
#else
	fprintf(stderr, "Client not compiled with SSL support\n");
#endif

	return 1;
}
/*----------------------------------------------------------------------------*/
static inline int
handle_read_event(struct thread_context *ctx, int sockid)
{
	char buf[BUF_SIZE];

	struct connection *conn = &ctx->connections[sockid];

#ifdef USE_SSL
	int ret = do_ssl_handshake(ctx, sockid);
	if (ret <= 0) {
		return ret;
	}
#endif
	
	int rd = 1;
	while (rd > 0) {
		rd = SOCKET_FUNC(read, ctx->core, sockid, buf, BUF_SIZE);
		if (rd <= 0)
			break;
		ctx->stats.bytes_rcvd += rd;

		// Verify the message contents
		for (int i = 0; i < rd; i++) {
			if (conn->content_error == 0 && buf[i] != msg[conn->msg_pos++]) {
				ctx->content_errors++;
				conn->content_error++;
				ctx->errors++;
			}
			if (conn->msg_pos >= msg_size) {
				conn->msgs_rcvd++;
				conn->msg_pos = 0;
			}
		}
	}

	if (rd == 0) {
		// Connection closed by host
		download_complete(ctx, sockid, conn);
		return 0;
	} else if (rd < 0 && errno != EAGAIN) {
		fprintf(stderr, "Error reading from socket\n");
		perror("read");
		ctx->read_errors++;
		ctx->errors++;
		close_connection(ctx, sockid);
		return -1;
	} else {

	}

	return 1;
}
/*----------------------------------------------------------------------------*/
void
print_running_stats(struct thread_context *ctx)
{
	printf("[CPU %d] Running Stats - Completes: %lu, Incompletes: %lu, "
			 "Started: %lu, Pending: %lu, Errors: %lu (content: %lu, "
			 "length: %lu, timeouts: %lu, epoll: %lu, read: %lu"
#ifdef USE_SSL
			 ", handshake: %lu"
#endif
			 ")\n",
			 ctx->core, ctx->completes, ctx->incompletes, ctx->started,
			 ctx->pending, ctx->errors, ctx->content_errors, ctx->length_errors,
			 ctx->timeouts, ctx->epoll_errors, ctx->read_errors
#ifdef USE_SSL
			 , ctx->handshake_errors
#endif
			 );
	fflush(stdout);
}
/*----------------------------------------------------------------------------*/
void
print_interval_stats(struct thread_context *ctx)
{
	double tp = (ctx->stats.bytes_rcvd * 8.0) / 1024 / 1024 / 1024;
	double arp = 0.0;
	if (ctx->stats.resp_entries > 0)
		arp = (ctx->stats.sum_resp_time / (double) ctx->stats.resp_entries);
	printf("[CPU %d] Interval Stats - M/s: %lu, Tp: %.2f Gbps, "
			 "Cnxs: %lu, Avg Resp Time: %.2f (us), Max Resp Time: %lu (us)\n",
			 ctx->core, ctx->stats.msgs_rcvd, tp, ctx->stats.connects,
			 arp, ctx->stats.max_resp_time);
	clean_interval_stats(&ctx->stats);
}
/*----------------------------------------------------------------------------*/
int
bind_cpu(int core)
{
	size_t n = (size_t) GetNumCPUs();

	assert(core >= 0 && core < (int) n);

	cpu_set_t *cmask = CPU_ALLOC(n);
	if (cmask == NULL)
		return -1;

	CPU_ZERO_S(n, cmask);
	CPU_SET_S(core, n, cmask);

	int ret = sched_setaffinity(0, n, cmask);
	CPU_FREE(cmask);

	return ret;
}
/*----------------------------------------------------------------------------*/
void *
run_client_thread(void *args)
{
	int core = *(int *) args;
	int maxevents = max_fds * FD_OVERHEAD_FACTOR;
	struct thread_context *ctx = &contexts[core];
	ctx = init_context(core);

#ifndef USE_LINUX
	mtcp_core_affinitize(core);
	if (ctx == NULL) {
		fprintf(stderr, "Failed to create context\n");
		return NULL;
	}

	srand(time(NULL));
	mtcp_init_rss(ctx->mctx, saddr, IP_RANGE, daddr, dport);

	struct mtcp_epoll_event *events = (struct mtcp_epoll_event *)
		calloc(maxevents, sizeof(struct mtcp_epoll_event));
#else
	bind_cpu(core);
	struct epoll_event *events = (struct epoll_event *)
		calloc(maxevents, sizeof(struct epoll_event));
#endif
	if (events == NULL) {
		perror("events calloc");
		exit(EXIT_FAILURE);
	}
	
	ctx->ep = SOCKET_FUNC(epoll_create, core, maxevents);
	if (ctx->ep < 0) {
		fprintf(stderr, "Failed to create epoll struct\n");
		exit(EXIT_FAILURE);
	}

	ctx->connections = (struct connection *)
		calloc(max_fds * FD_OVERHEAD_FACTOR, sizeof(struct connection));
	if (ctx->connections == NULL) {
		perror("connections calloc");
		exit(EXIT_FAILURE);
	}

	struct timeval curr_tv, prev_tv;
	gettimeofday(&prev_tv, NULL);

	printf("[CPU %d] Launching client\n", core);
	
	while (1) {
		
		gettimeofday(&curr_tv, NULL);
		if (curr_tv.tv_sec > prev_tv.tv_sec && curr_tv.tv_usec > prev_tv.tv_usec) {
			print_interval_stats(ctx);
			print_running_stats(ctx);
			prev_tv = curr_tv;
		}

		while (ctx->pending < concurrency) {
			if (create_connection(ctx) < 0) {
				break;
			}
		}

		int nevents = SOCKET_FUNC(epoll_wait, core, ctx->ep, events, maxevents, -1);

		if (nevents < 0) {
			if (errno != EINTR) {
				perror("epoll_wait");
			}
			break;
		}

		for (int i = 0; i < nevents; i++) {

			if (i % 100 == 0) {
				gettimeofday(&curr_tv, NULL);
				if (curr_tv.tv_sec > prev_tv.tv_sec && curr_tv.tv_usec > prev_tv.tv_usec) {
					print_interval_stats(ctx);
					print_running_stats(ctx);
					prev_tv = curr_tv;
				}
			}
			
#ifndef USE_LINUX
			int efd = events[i].data.sockid;
#else
			int efd = events[i].data.fd;
#endif
			
			if (IS_EVENT_TYPE(events[i].events, EPOLLERR)) {

				int err;
				socklen_t len = sizeof(err);

				ctx->errors++;
				if (SOCKET_FUNC(getsockopt, core, efd, SOL_SOCKET,
									 SO_ERROR, (void *) &err, &len) == 0) {
					if (err == ETIMEDOUT)
						ctx->timeouts++;
					else
						ctx->epoll_errors++;
				}
				close_connection(ctx, efd);
				
			} else if (IS_EVENT_TYPE(events[i].events, EPOLLIN)) {

				handle_read_event(ctx, efd);
				
			} else if (IS_EVENT_TYPE(events[i].events, EPOLLOUT)) {

#ifdef USE_SSL
				if (do_ssl_handshake(ctx, efd) <= 0) {
					ctx->errors++;
					ctx->handshake_errors++;
					close_connection(ctx, efd);
				}
#endif
				
			}
		}
	}

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

#ifndef USE_LINUX
	char *conf_file = "mtcp.conf";
#endif

	core_limit = num_cores;
	main_thread = pthread_self();
	msgs_per_conn = 0;
	msg_size = 0;

	int o;
	while (-1 != (o = getopt(argc, argv, "N:f:c:b:s:k:l:h"))) {
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
			break;
		case 's':
			msg_size = mystrtol(optarg, 10);
			if (msg_size <= 0) {
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
		case 'l':
#ifdef USE_SSL
			use_global_lock = TRUE;
#else
			fprintf(stderr, "SSL is not enabled\n");
#endif
			break;
		case 'h':
			printf("Usage: %s max_concurrency host port "
					 "[-f <mtcp_conf_file>] "
					 "[-s <msg size>] [-k <msgs per connection>] "
					 "[-N num_cores] [-c <per-processs core_id>] [-h]\n",
					 argv[0]);
			return EXIT_SUCCESS;
		default:
			fprintf(stderr, "Unrecognized option: %c\n", o);
	   }
	}

	int max_concurrency = mystrtol(argv[optind++], 10);
	char *host = argv[optind++];
	int port = mystrtol(argv[optind++], 10);

	daddr = inet_addr(host);
	dport = htons(port);
	saddr = INADDR_ANY;

	concurrency = max_concurrency / core_limit;
	max_fds = concurrency * FD_OVERHEAD_FACTOR;

	// Generate ascii message of s characters
	if (msg_size > 0) {
		msg = (char *) calloc(msg_size + 1, sizeof(char));
		msg[msg_size] = '\0';
		int c = 65;
		for (int i = 0; i < msg_size; i++) {
			msg[i] = (char) c++;
			if (c >= 91)
				c = 65;
		}
		fprintf(stderr, "Message being received: %s\n", msg);
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
	mcfg.max_concurrency = max_fds;
	mcfg.max_num_buffers = max_fds;
	mtcp_setconf(&mcfg);

	mtcp_register_signal(SIGINT, signal_handler);
#endif

#ifdef USE_SSL
	init_openssl(use_global_lock, CRYPTO_num_locks());
#ifndef USE_LINUX
	ssl_ctx = create_ssl_context(g_ctx);
#else
	ssl_ctx = create_ssl_context();
#endif
	configure_ssl_context(ssl_ctx);
#endif

	int cores[MAX_CPUS];
	int starting_core = (process_cpu == -1) ? 0 : process_cpu;
	// Spawn client threads
	for (int i = starting_core; i < core_limit; i++) {
		cores[i] = i;
		
		if (pthread_create(&app_thread[i], NULL,
								 run_client_thread, (void *) &cores[i])) {
			perror("pthread_create");
			abort();
		}
	}

	for (int i = starting_core; i < core_limit; i++) {
		pthread_join(app_thread[i], NULL);
	}

#ifdef USE_SSL
	cleanup_openssl(use_global_lock, CRYPTO_num_locks());
	// TODO: Move free cleanup, requires messenger to be refactored
	SSL_CTX_free(ssl_ctx);
#endif

#ifndef USE_LINUX
	mtcp_destroy();
#endif

	if (msg != NULL)
		free(msg);

	return EXIT_SUCCESS;
}
/*----------------------------------------------------------------------------*/
