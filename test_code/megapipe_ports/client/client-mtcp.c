/**
 * Modified the client-ports code to use mTCP to better stress test the performance of the server.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif             

/* Header Include Declarations */
/* Core Headers */
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
/* For socket(2) and connect(2) */
#include <sys/socket.h>
/* For IPv4 */
#include <netinet/in.h>
#include <netinet/ip.h>
/* For inet_aton(3) */
#include <arpa/inet.h>
/* For memset(3) */
#include <string.h>
/* For pthreads */
#include <pthread.h>
/* For epoll */
#include <sys/epoll.h>
/* For errno */
#include <errno.h>
/* used in bind_cpu() */
#include <sched.h>
#include "client-mtcp.h"

/* signal handling */
#include <signal.h>
/* For setitimer(2) */
#include <sys/time.h>

#include <unistd.h>

/* For mtcp */
#include <mtcp_epoll.h>
/*-------------------------------------------------------------------------------------------------------*/
int num_threads = MAX_THREADS;
int reqsize = 64;
int ressize = 64;
int msgs_per_conn = 0;
int conns_per_thread = 32;
int num_ports = 1;
int port_gap = 1;
struct threaddata tdata[MAX_THREADS];
mctx_t g_ctx[MAX_THREADS];
/*-------------------------------------------------------------------------------------------------------*/
int
get_num_cpus()                             
{                                              
	return sysconf(_SC_NPROCESSORS_ONLN);  
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
stop_threads(void) 
{
	int i;
	
	for(i = 0; i < num_threads; i++) {
		if(pthread_cancel(tdata[i].thread) != 0) {
			perror("Unable to cancel thread");
		}
	}
	
	for(i = 0; i < num_threads; i++) {
		if(pthread_join(tdata[i].thread, NULL) != 0) {
			perror("Error joining thread");
		}
	}

	for (i = 0; i < num_threads; i++) {
	   mtcp_destroy_context(g_ctx[i]);
	}
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
				fprintf(stderr, "(%lu,", tdata[i].total_recvd - tdata[i].total_recvd_prev);
				tdata[i].total_recvd_prev = tdata[i].total_recvd;

				fprintf(stderr, "%lu)", tdata[i].total_sent - tdata[i].total_sent_prev);
				tdata[i].total_sent_prev = tdata[i].total_sent;
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
int
main(int argc, char *argv[]) 
{
	int param_destport = DEST_PORT;
	char *param_destip = DEST_IP;
	int i;

	printf("Usage: %s [OPTIONS] [remote IP] [remote port] [source IP] [source IP]...\n", argv[0]);
	printf("  -t # of threads (default: %d)\n", num_threads);
	printf("  -c # of concurrent connections per thread (default: %d)\n", conns_per_thread);
	printf("  -q RPC request size (default: %d)\n", reqsize);
	printf("  -r RPC response size (default: %d)\n", ressize);
	printf("  -m # of messages per connection (default: %d, no RPC-like test if 0)\n", msgs_per_conn);
	printf("  -p # of ports (default: %d)\n", num_ports);
	printf("  -g port gap (default: %d)\n", port_gap);

	while (argc >= 3) {
		if (strcmp(argv[1], "-t") == 0) {
			sscanf(argv[2], "%d", &num_threads);
			assert(1 <= num_threads && num_threads <= MAX_THREADS && num_threads <= get_num_cpus());
		} else if (strcmp(argv[1], "-q") == 0) {
			sscanf(argv[2], "%d", &reqsize);
			assert(8 <= reqsize && reqsize <= BUFSIZE);
		} else if (strcmp(argv[1], "-r") == 0) {
			sscanf(argv[2], "%d", &ressize);
			assert(4 <= ressize && ressize <= BUFSIZE);
		} else if (strcmp(argv[1], "-m") == 0) {
			sscanf(argv[2], "%d", &msgs_per_conn);
			assert(0 <= msgs_per_conn);
		} else if (strcmp(argv[1], "-c") == 0) {
			sscanf(argv[2], "%d", &conns_per_thread);
			assert(1 <= conns_per_thread);
		} else if (strcmp(argv[1], "-p") == 0) {
			sscanf(argv[2], "%d", &num_ports);
			assert(1 <= num_ports && num_ports <= num_threads);
		} else if (strcmp(argv[1], "-g") == 0) {
			sscanf(argv[2], "%d", &port_gap);
		} else
			break;

		argc -= 2;
		argv += 2;
	}

	if (argc >= 2)
		param_destip = argv[1];

	if (argc >= 3)
		sscanf(argv[2], "%d", &param_destport);

	printf("\n");
	printf("# of threads: %d (%d concurrent connections per thread)\n", num_threads, conns_per_thread);
	printf("Remote address: %s:%d\n", param_destip, param_destport);

	if (msgs_per_conn == 0)
		printf("RPC-like test is disabled\n");
	else
		printf("%d RPC queries per connection (request size %d, response size %d)\n", msgs_per_conn, reqsize, ressize);

	struct mtcp_conf mcfg;
	mtcp_getconf(&mcfg);
	mcfg.num_cores = num_threads;
	mtcp_setconf(&mcfg);

	int ret = mtcp_init("config/mtcp.conf");
	if (ret) {
		fprintf(stderr, "Failed to initialize mtcp\n");
		exit(EXIT_FAILURE);
	}
	mtcp_getconf(&mcfg);
	mcfg.max_concurrency = conns_per_thread * 3;
	mcfg.max_num_buffers = conns_per_thread * 3;
	mtcp_setconf(&mcfg);

	for(i = 0; i < num_threads; i++) {
		/* Store conection info */
		if(inet_aton(param_destip, &(tdata[i].destip)) == 0) {
			fprintf(stderr, "Invalid destination IP\n");
			exit_cleanup();
		}

		tdata[i].destport = param_destport + (i % num_ports) * port_gap;

		if(argc > (3 + i)) {
			if(inet_aton(argv[3 + i], &(tdata[i].srcip)) == 0) {
				fprintf(stderr, "Invalid source IP\n");
				exit_cleanup();
			}
			printf("Source IP address of thread %d: %s\n", i, argv[3 + i]);
		} else {
			tdata[i].srcip.s_addr = INADDR_ANY;
			printf("Source IP address of thread %d: INADDR_ANY\n", i);
		}

		tdata[i].cpu_id = i;

		if(pthread_create(&tdata[i].thread, NULL, client_thread, &(tdata[i])) != 0) {
			perror("Unable to create client thread");
			exit_cleanup();
		}
	}

	mask_signal();
	init_timer();
	do_stats();

	return EXIT_SUCCESS;
}
/*-------------------------------------------------------------------------------------------------------*/
int
send_rpc(int epfd, char *buf, struct conn_context *ctx, int cpu_id, mctx_t mctx)
{
	struct mtcp_epoll_event evt;
	int ret;

	if (reqsize == ctx->send_left) {
		*((int *)buf) = reqsize;
		*((int *)(buf + 4)) = ressize;
	}
    
	ret = mtcp_write(mctx, ctx->sockid, buf, ctx->send_left);
	tdata[cpu_id].total_sent += ret;
	if (ret < 8)
		return -1;

	assert(ret <= ctx->send_left);
	ctx->send_left -= ret;

	if (ctx->send_left == 0) {
		ctx->msg_cnt++;
		ctx->recv_left = ressize;
		ctx->send_left = reqsize;
		evt.events = MTCP_EPOLLIN | MTCP_EPOLLHUP | MTCP_EPOLLERR;
		evt.data.ptr = ctx;

		if (mtcp_epoll_ctl(mctx, epfd, MTCP_EPOLL_CTL_MOD, ctx->sockid, &evt) != 0) {
			perror("Unable to add socket to epoll");
			exit_cleanup();
		}
	} else {
		evt.events = MTCP_EPOLLOUT | MTCP_EPOLLHUP | MTCP_EPOLLERR;
		evt.data.ptr = ctx;

		if (mtcp_epoll_ctl(mctx, epfd, MTCP_EPOLL_CTL_MOD, ctx->sockid, &evt) != 0) {
			perror("Unable to add socket to epoll");
			exit_cleanup();
		}
	}

	return 0;
}
/*-------------------------------------------------------------------------------------------------------*/
void *
client_thread(void *arg) 
{
	struct threaddata *tdata = (struct threaddata *)arg;
	int i;

	struct conn_context ctxs[conns_per_thread];

	mtcp_core_affinitize(tdata->cpu_id);

	g_ctx[tdata->cpu_id] = mtcp_create_context(tdata->cpu_id);
	if (g_ctx[tdata->cpu_id] == NULL) {
		fprintf(stderr, "Failed to create mtcp context\n");
		return NULL;
	}
	mctx_t mctx = g_ctx[tdata->cpu_id];

	mtcp_init_rss(mctx, tdata->srcip.s_addr, IP_RANGE, tdata->destip.s_addr, tdata->destport);

	if((tdata->epfd = mtcp_epoll_create(mctx, conns_per_thread * 3)) == -1) {
		perror("Unable to create epoll FD");
		exit_cleanup();
	}

	printf("CPU%d connecting to port %d\n", tdata->cpu_id, tdata->destport);
	/* Create the initial pool of connections */
	for (i = 0; i < conns_per_thread; i++)
		conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, &ctxs[i], mctx);

	while (1) {
		int num_events;
		int ret;
		char buf[BUFSIZE];
		struct mtcp_epoll_event evts[EVENTS_PER_BATCH];

		num_events = mtcp_epoll_wait(mctx, tdata->epfd, evts, EVENTS_PER_BATCH, -1);


		if (num_events <= 0) {
			if (errno == EINTR)
				continue;
			perror("epoll_wait() error");
			exit_cleanup();
		}

		for (i = 0; i < num_events; i++) {
			struct conn_context *ctx = (struct conn_context *)evts[i].data.ptr;
			int broken = 0;

			if (evts[i].events & (MTCP_EPOLLHUP | MTCP_EPOLLERR)) {
				/* retry */
				mtcp_close(mctx, ctx->sockid);
				conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx, mctx);
				continue;
			}
   
			if (evts[i].events == MTCP_EPOLLOUT) {
				if (msgs_per_conn == 0) {
					mtcp_close(mctx, ctx->sockid);
					conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx, mctx);
				} else {
					broken = send_rpc(tdata->epfd, buf, ctx, tdata->cpu_id, mctx);
					tdata->trancnt++;
				}
			} else if (evts[i].events == MTCP_EPOLLIN) {
				ret = mtcp_read(mctx, ctx->sockid, buf, ressize);
				if (ret < 0) {
					if (errno == EAGAIN) {
						ret = 0;
					} else {
						perror("mtcp_read");
						mtcp_close(mctx, ctx->sockid);
						conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx, mctx);
						continue;
					}
				}
				/*assert(ret > 0);
				  assert(ret <= ctx->recv_left);*/
				tdata->total_recvd += ret;
				ctx->recv_left -= ret;

				if (ctx->recv_left > 0)
					continue;
				
				if (ctx->msg_cnt < msgs_per_conn) {
					broken = send_rpc(tdata->epfd, buf, ctx, tdata->cpu_id, mctx);
					tdata->trancnt++;
				} else {
					mtcp_close(mctx, ctx->sockid);
					conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx, mctx);
				}
			} else
				assert(0);

			if (broken) {
				mtcp_close(mctx, ctx->sockid);
				conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx, mctx);
			}
		}
	}

	return NULL;
}
/*-------------------------------------------------------------------------------------------------------*/
void
conn_client(struct in_addr destip, uint16_t destport, struct in_addr srcip, 
				int epfd, struct conn_context *ctx, mctx_t mctx) {
	int skt;
	struct sockaddr_in destaddr, srcaddr;
	socklen_t daddrlen = sizeof(destaddr), saddrlen = sizeof(srcaddr);
	struct mtcp_epoll_event evt;
	int status;

	/* Open the socket */
	if((skt = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Unable to open socket");
		exit_cleanup();
	}
	if (mtcp_setsock_nonblock(mctx, skt) < 0) {
		fprintf(stderr, "Failed to set socket in nonblocking mode\n");
		exit_cleanup();
	}

	/* Configure address parameters for connection */
	memset(&destaddr, 0, daddrlen);
	destaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(destport);
	destaddr.sin_addr = destip;

	memset(&srcaddr, 0, saddrlen);
	srcaddr.sin_family = AF_INET;
	srcaddr.sin_addr = srcip;

	/* Bind the socket to the src IP */
	if(mtcp_bind(mctx, skt, (struct sockaddr *)&srcaddr, saddrlen) == -1) {
		perror("Unable to bind");
		exit_cleanup();
	}

	ctx->sockid = skt;
	ctx->msg_cnt = 0;
	ctx->send_left = reqsize;
    
	/* Add the socket to epoll */
	evt.events = MTCP_EPOLLOUT | MTCP_EPOLLHUP | MTCP_EPOLLERR;
	evt.data.ptr = ctx;

	if(mtcp_epoll_ctl(mctx, epfd, MTCP_EPOLL_CTL_ADD, skt, &evt) != 0) {
		perror("Unable to add socket to epoll");
		exit_cleanup();
	}

	status = mtcp_connect(mctx, skt, (struct sockaddr *)&destaddr, daddrlen);

	if(status != -1 || errno != EINPROGRESS) {
		perror("nonblocking connect() failed");
		exit_cleanup();
	}
}
/*-------------------------------------------------------------------------------------------------------*/
void
exit_cleanup(void) {
	exit(EXIT_FAILURE);
}
/*-------------------------------------------------------------------------------------------------------*/
