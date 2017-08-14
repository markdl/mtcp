/**
 * Simple server.
 *
 * Measures number of new client connections per second.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Header Include Declarations */
/* Core Headers */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
/* For socket(2), bind(2), listen(2), and accept(2) */
#include <sys/socket.h>
/* For close(2) */
#include <unistd.h>
/* For IPv4 */
#include <netinet/in.h>
#include <netinet/ip.h>
/* For inet_aton(3) */
#include <arpa/inet.h>
/* For memset(3) */
#include <string.h>
/* For sigaction(2) */
#include <signal.h>
/* For setitimer(2) */
#include <sys/time.h>
/* For pthreads */
#include <pthread.h>
/* For epoll */
#include <sys/epoll.h>
/* used in bind_cpu() */
#include <sched.h>

#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include "server-mtcp.h"
/*-------------------------------------------------------------------------------------------------------*/
/* Global - per-thread data */
struct threaddata tdata[MAX_THREADS];

int num_threads = MAX_THREADS;

#define MAX_FLOW_NUM  (100000)
#define RCVBUF_SIZE (1*1024)
#define SNDBUF_SIZE (1*1024)
#define HT_SUPPORT 0
/*-------------------------------------------------------------------------------------------------------*/
int
get_num_cpus()
{
        return sysconf(_SC_NPROCESSORS_ONLN);
}
/*-------------------------------------------------------------------------------------------------------*/
int
bind_cpu(int cpu)
{
        cpu_set_t *cmask;
        size_t n;
        int ret;
	
        n = get_num_cpus();
	
        if (cpu < 0 || cpu >= (int)n) {
                errno = -EINVAL;
                return -1;
        }
	
        cmask = CPU_ALLOC(n);
        if (cmask == NULL)
                return -1;
	
        CPU_ZERO_S(n, cmask);
        CPU_SET_S(cpu, n, cmask);
	
        ret = sched_setaffinity(0, n, cmask);
	
        CPU_FREE(cmask);
	
        return ret;
}
/*-------------------------------------------------------------------------------------------------------*/
int
main(int argc, char *argv[]) 
{
	int param_port = SERVER_PORT;
	char param_listenip[512];
	struct in_addr listenip;
	int o;
	
	printf("Usage: %s [-i listen-IP] [-p listen-port] [-n #-of-threads]\n", 
	       argv[0]);
	
	strcpy(param_listenip, SERVER_IP);
	
	while (-1 != (o = getopt(argc, argv, "i:p:n:"))) {
		switch (o) {
		case 'i':
			strcpy(param_listenip, optarg);
			break;
		case 'p':
			param_port = atoi(optarg);
			break;
		case 'n':
			num_threads = atoi(optarg);
			break;
		}
	}

	printf("# of CPUs: %d\n", get_num_cpus());
	assert(num_threads >= 1 && num_threads <= get_num_cpus());
	
	if(inet_aton(param_listenip, &listenip) == 0) {
		fprintf(stderr, "Invalid listen IP\n");
		exit_cleanup();
	}
	
	printf("# of threads: %d\n", num_threads);
	printf("Listening address: %s:%d\n", param_listenip, param_port);
	
	init_server();
	mask_signal();
	init_threads(listenip, param_port);
	init_timer();
	do_stats();
	
	return EXIT_SUCCESS;
}
/*-------------------------------------------------------------------------------------------------------*/
void
mask_signal(void)
{
	sigset_t siglist;
	
	/* Mask SIGALRM and SIGINT */
	if(sigemptyset(&siglist) == -1) {
		perror("Unable to initialize signal list");
		exit_cleanup();
	}
	
	if(sigaddset(&siglist, SIGALRM) == -1) {
		perror("Unable to add SIGALRM signal to signal list");
		exit_cleanup();
	}
	
	if(sigaddset(&siglist, SIGINT) == -1) {
		perror("Unable to add SIGINT signal to signal list");
		exit_cleanup();
	}
	
	if(pthread_sigmask(SIG_BLOCK, &siglist, NULL) != 0) {
		perror("Unable to change signal mask");
		exit_cleanup();
	}
}
/*-------------------------------------------------------------------------------------------------------*/
void
init_timer(void)
{
	struct itimerval interval;
	
	interval.it_interval.tv_sec = 1;
	interval.it_interval.tv_usec = 0;
	interval.it_value.tv_sec = 1;
	interval.it_value.tv_usec = 0;
	
	if(setitimer(ITIMER_REAL, &interval, NULL) != 0) {
		perror("Unable to set interval timer");
		exit_cleanup();
	}
}
/*-------------------------------------------------------------------------------------------------------*/
void
init_server() 
{
	struct mtcp_conf mcfg;
	mtcp_getconf(&mcfg);
	mcfg.num_cores = num_threads;
	mtcp_setconf(&mcfg);
	
	/* initialize the mtcp context */
	if (mtcp_init("config/mtcp.conf")) {
		fprintf(stderr, "Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}
	
	mtcp_getconf(&mcfg);
	mcfg.max_concurrency = mcfg.max_num_buffers = MAX_CONNS_PER_THREAD;
	//mcfg.rcvbuf_size = RCVBUF_SIZE;
	//mcfg.sndbuf_size = SNDBUF_SIZE;
	mtcp_setconf(&mcfg);
	
	return;
}
/*-------------------------------------------------------------------------------------------------------*/
void
init_threads(struct in_addr ip, uint16_t port) 
{
	int i;

	for(i = 0; i < num_threads; i++) {
		tdata[i].trancnt = 0;
#ifdef VERBOSE
		tdata[i].total_recvd = tdata[i].total_recvd_prev = 0;
		tdata[i].total_sent = tdata[i].total_sent_prev = 0;
#endif
		tdata[i].cpu_id = i;
		tdata[i].ip = ip;
		tdata[i].port = port;
		
		if(pthread_create(&(tdata[i].thread), NULL, process_clients,
				  &(tdata[i])) != 0) {
			perror("Unable to create worker thread");
			exit_cleanup();
		}
	}
}
/*-------------------------------------------------------------------------------------------------------*/
struct context_pool *
init_pool(int size)
{
	struct context_pool *ret;
	int i;
	
	assert(size > 0);
	
	ret = malloc(sizeof(struct context_pool));
	assert(ret);
	
	ret->arr = malloc(sizeof(struct conn_context) * size);
	assert(ret->arr);
	
	ret->total = size;
	ret->allocated = 0;
	ret->next_idx = 0;
	
	for (i = 0; i < size - 1; i++)
		ret->arr[i].next_idx = i + 1;
	
	ret->arr[size - 1].next_idx = -1;
	
	return ret;
}
/*-------------------------------------------------------------------------------------------------------*/
struct conn_context *
alloc_context(struct context_pool *pool)
{
	struct conn_context *ret;
	
	assert(pool->allocated < pool->total);
	pool->allocated++;
	
	ret = &pool->arr[pool->next_idx];
	pool->next_idx = pool->arr[pool->next_idx].next_idx;
	
	ret->fd = 0;
	ret->next_idx = -1;
	
	return ret;
}
/*-------------------------------------------------------------------------------------------------------*/
void 
free_context(struct context_pool *pool, struct conn_context *context)
{
	assert(pool->allocated > 0);
	pool->allocated--;
	
	context->next_idx = pool->next_idx;
	pool->next_idx = context - pool->arr;
}
/*-------------------------------------------------------------------------------------------------------*/
void *
process_clients(void *arg) 
{
	struct context_pool *pool;
	struct threaddata *mydata = (struct threaddata *)arg;
	cpu_set_t cpu_mask;
	int ret, listener, ep, maxevents, nevents, i;
	int sockid = -1;
	struct sockaddr_in saddr;
	struct mtcp_epoll_event ev, *events;
	
#if HT_SUPPORT
	mtcp_core_affinitize(mydata->cpu_id + (num_threads));
#else
	mtcp_core_affinitize(mydata->cpu_id);
#endif
	pool = init_pool(MAX_CONNS_PER_THREAD);
	
	if(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ret) != 0) {
		perror("Unable to set thread cancellation type");
		exit_cleanup();
	}

	CPU_ZERO(&cpu_mask);
	CPU_SET(mydata->cpu_id, &cpu_mask);
	
	mydata->mctx = mtcp_create_context(mydata->cpu_id);
	if (!mydata->mctx) {
		fprintf(stderr, "Failed to create mtcp context!\n");
		exit(EXIT_FAILURE);
	}
	listener = mtcp_socket(mydata->mctx, AF_INET, SOCK_STREAM, 0);
	if (listener < 0) {
		fprintf(stderr, "Failed to create listening socket!\n");
		exit(EXIT_FAILURE);
	}
	ret = mtcp_setsock_nonblock(mydata->mctx, listener);
	if (ret < 0) {
		fprintf(stderr, "Failed to set socket in nonblocking mode.\n");
		exit(EXIT_FAILURE);
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr = mydata->ip;
	/* saddr.sin_addr.s_addr = INADDR_ANY; */
	saddr.sin_port = htons(mydata->port);
	ret = mtcp_bind(mydata->mctx, listener, 
			(struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
	if (ret < 0) {
		fprintf(stderr, "Failed to bind to the listening socket!\n");
		exit(EXIT_FAILURE);
	}
	
	ret = mtcp_listen(mydata->mctx, listener, LISTEN_BACKLOG);
	if (ret < 0) {
		fprintf(stderr, "mtcp_listen() failed!\n");
		exit(EXIT_FAILURE);
	}
	
	maxevents = MAX_FLOW_NUM * 3;
	ep = mtcp_epoll_create(mydata->mctx, maxevents);
	if (ep < 0) {
		fprintf(stderr, "Failed to create epoll struct!n");
		exit(EXIT_FAILURE);
	}
	
	events = (struct mtcp_epoll_event *)
		calloc(maxevents, sizeof(struct mtcp_epoll_event));
	if (!events) {
		fprintf(stderr, "Failed to allocate events!\n");
		exit(EXIT_FAILURE);
	}
	
	ev.events = MTCP_EPOLLIN;
	ev.data.sockid = listener;
	mtcp_epoll_ctl(mydata->mctx, ep, MTCP_EPOLL_CTL_ADD, listener, &ev);
	
	while (1) {
		struct conn_context *context;
		nevents = mtcp_epoll_wait(mydata->mctx, ep, events, maxevents, -1);
		if (nevents < 0) {
			fprintf(stderr, "mtcp_epoll_wait failed! ret: %d\n", nevents);
			break;
		}

		for (i = 0; i < nevents; i++) {
			/* ACCEPT */
			if (events[i].data.sockid == listener) {
				while (1) {
					sockid = mtcp_accept(mydata->mctx, listener, NULL, NULL);

					if (sockid >= 0) {
						ev.events = MTCP_EPOLLIN;
						context = alloc_context(pool);
						context->fd = sockid;
						context->recv_left = context->send_left = 0;
						ev.data.ptr = context;
						ret = mtcp_setsock_nonblock(mydata->mctx, sockid);
						if (ret < 0) {
							fprintf(stderr, "Failed to set socket in nonblocking mode.\n");
							exit(EXIT_FAILURE);
						}
						mtcp_epoll_ctl(mydata->mctx, ep, 
							       MTCP_EPOLL_CTL_ADD, sockid, &ev);
					} else {
						if (errno != EAGAIN) {
							fprintf(stderr, "mtcp_accept() error %s\n", 
								strerror(errno));
						}
						break;
					}
				}
			} else if (events[i].events == MTCP_EPOLLIN) {
				int reqsize, ressize;
				context = events[i].data.ptr;
				/* READ */
				while ((ret = mtcp_read(mydata->mctx, 
							context->fd, context->buf, MAX_BUFSIZE)) > 0) {
					if (context->recv_left == 0 && context->send_left == 0) {
						reqsize = *((int *)context->buf);
						assert(ret <= reqsize);
						assert(ret >= 8);

						ressize = *((int *)(context->buf + 4));
						assert(4 <= ressize && ressize <= MAX_BUFSIZE);

						context->recv_left = reqsize - ret;
						context->send_left = ressize;
					} else {
						assert(ret <= context->recv_left);
						context->recv_left -= ret;
					}
#ifdef VERBOSE
					mydata->total_recvd += ret;
#endif

					if (context->recv_left == 0) {
						break;
					}
				}

				/* CLOSE/RESET */
				if (ret == 0) {
					mtcp_epoll_ctl(mydata->mctx, ep, 
						       MTCP_EPOLL_CTL_DEL, context->fd, 0);
					//mtcp_abort(mydata->mctx, context->fd);
					mtcp_close(mydata->mctx, context->fd);
					free_context(pool, context);
				} else if (ret < 0 && errno != EAGAIN) {
					fprintf(stderr, "mtcp_read() error: %d(%s)\n", errno, strerror(errno));
					//mtcp_abort(mydata->mctx, context->fd);
					mtcp_close(mydata->mctx, context->fd);
					free_context(pool, context);
				}
				/* WRITE */
				if (context->recv_left == 0 && context->send_left > 0) {
					ret = mtcp_write(mydata->mctx,
							 context->fd, context->buf, context->send_left);
					if (ret != -1) {
						mydata->trancnt += 1;
#ifdef VERBOSE
						mydata->total_sent += ret;
#endif
						if (ret != context->send_left)
							fprintf(stderr, "context->send_left: %u, ret: %u\n",
								context->send_left, ret);
						context->send_left -= ret;
					}
					else {
						fprintf(stderr, "mtcp_write failed!\n");
					}
				}
			}
		}
	}

	return NULL;
}
/*-------------------------------------------------------------------------------------------------------*/
void 
do_stats(void) 
{
	sigset_t siglist;
	int signum;
	int i;
	
	/*
	 * Note that we're interested in two signal types:
	 *  1. SIGALRM -- for periodic collection of statistics
	 *  2. SIGINT -- to gracefully terminate
	 */
	
	if(sigemptyset(&siglist) == -1) {
		perror("Unable to initalize stats signal list");
		exit_cleanup();
	}
	
	if(sigaddset(&siglist, SIGALRM) == -1) {
		perror("Unable to add SIGALRM signal to stats signal list");
		exit_cleanup();
	}
	
	
	if(sigaddset(&siglist, SIGINT) == -1) {
		perror("Unable to add SIGINT signal to stats signal list");
		exit_cleanup();
	}
	
	while(1) {
		if(sigwait(&siglist, &signum) != 0) {
			perror("Error waiting for signal");
			exit_cleanup();
		}
		
		if(signum == SIGALRM) {
			uint64_t trancnt = 0;
						
			for(i = 0; i < num_threads; i++) {
				trancnt += tdata[i].trancnt - tdata[i].trancnt_prev;
				fprintf(stderr, "%8lu", tdata[i].trancnt - tdata[i].trancnt_prev);
				tdata[i].trancnt_prev = tdata[i].trancnt;
#ifdef VERBOSE
				fprintf(stderr, "(%lu,", tdata[i].total_recvd - tdata[i].total_recvd_prev);
				tdata[i].total_recvd_prev = tdata[i].total_recvd;

				fprintf(stderr, "%lu)", tdata[i].total_sent - tdata[i].total_sent_prev);
				tdata[i].total_sent_prev = tdata[i].total_sent;
#endif
			}
			fprintf(stderr, "\tTotal %8lu\n", trancnt);
			
		} else if(signum == SIGINT) {
			printf("\nExiting...\n");
			stop_threads();
			break;
		}
	}
}
/*-------------------------------------------------------------------------------------------------------*/
void 
exit_cleanup(void) 
{
	stop_threads();
	exit(EXIT_FAILURE);
}
/*-------------------------------------------------------------------------------------------------------*/
void
stop_threads(void) 
{
	int i;
	
	for(i = 0; i < num_threads; i++) {
		mtcp_destroy_context(tdata[i].mctx);
		if(pthread_cancel(tdata[i].thread) != 0) {
			perror("Unable to cancel thread");
		}
	}
	
	for(i = 0; i < num_threads; i++) {
		if(pthread_join(tdata[i].thread, NULL) != 0) {
			perror("Error joining thread");
		}
	}
}
/*-------------------------------------------------------------------------------------------------------*/
