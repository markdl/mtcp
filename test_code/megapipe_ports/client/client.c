/**
 * Simple client.
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
/* For close(2) */
#include <unistd.h>
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
#include "client.h"

#ifdef VERBOSE
/* signal handling */
#include <signal.h>
/* For setitimer(2) */
#include <sys/time.h>
#endif
/*-------------------------------------------------------------------------------------------------------*/
int num_threads = MAX_THREADS;
int reqsize = 64;
int ressize = 64;
int msgs_per_conn = 0;
int conns_per_thread = 32;
struct threaddata tdata[MAX_THREADS];
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
#ifdef VERBOSE
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
#endif /* VERBOSE */
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

    for(i = 0; i < num_threads; i++) {
        /* Create the epoll FD for this thread */
        if((tdata[i].epfd = epoll_create(conns_per_thread)) == -1) {
            perror("Unable to create epoll FD");
            exit_cleanup();
        }

        /* Store connection info */
        if(inet_aton(param_destip, &(tdata[i].destip)) == 0) {
            fprintf(stderr, "Invalid destination IP\n");
            exit_cleanup();
        }

        tdata[i].destport = param_destport;

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

#ifdef VERBOSE
    mask_signal();
    init_timer();
    do_stats();
#else
    pause();
#endif

    return EXIT_SUCCESS;
}
/*-------------------------------------------------------------------------------------------------------*/
#ifdef VERBOSE
int
send_rpc(int epfd, char *buf, struct conn_context *ctx, int cpu_id)
#else
int
send_rpc(int epfd, char *buf, struct conn_context *ctx)
#endif
{
    struct epoll_event evt;
    int ret;

    if (reqsize == ctx->send_left) {
        *((int *)buf) = reqsize;
        *((int *)(buf + 4)) = ressize;
    }
    
    ret = write(ctx->fd, buf, ctx->send_left);
#ifdef VERBOSE
    tdata[cpu_id].total_sent += ret;
#endif
    if (ret < 8)
        return -1;

    assert(ret <= ctx->send_left);
    ctx->send_left -= ret;

    if (ctx->send_left == 0) {
        ctx->msg_cnt++;
        ctx->recv_left = ressize;
        ctx->send_left = reqsize;
        evt.events = EPOLLIN | EPOLLHUP | EPOLLERR;
        evt.data.ptr = ctx;

        if (epoll_ctl(epfd, EPOLL_CTL_MOD, ctx->fd, &evt) != 0) {
            perror("Unable to add socket to epoll");
            exit_cleanup();
        }
    } else {
        evt.events = EPOLLOUT | EPOLLHUP | EPOLLERR;
        evt.data.ptr = ctx;

        if (epoll_ctl(epfd, EPOLL_CTL_MOD, ctx->fd, &evt) != 0) {
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

    bind_cpu(tdata->cpu_id);

    /* Create the initial pool of connections */
    for (i = 0; i < conns_per_thread; i++)
        conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, &ctxs[i]);

    while (1) {
        int num_events;
        int ret;
        char buf[BUFSIZE];
        struct epoll_event evts[EVENTS_PER_BATCH];

        num_events = epoll_wait(tdata->epfd, evts, EVENTS_PER_BATCH, -1);

        if (num_events <= 0) {
            perror("epoll_wait() error");
            exit_cleanup();
        }

        for (i = 0; i < num_events; i++) {
            struct conn_context *ctx = (struct conn_context *)evts[i].data.ptr;
            int broken = 0;

            if (evts[i].events & (EPOLLHUP | EPOLLERR)) {
                /* retry */
                close(ctx->fd);
                conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx);
                continue;
            }
   
            if (evts[i].events == EPOLLOUT) {
                if (msgs_per_conn == 0) {
                    close(ctx->fd);
                    conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx);
                } else {
#ifdef VERBOSE
		    broken = send_rpc(tdata->epfd, buf, ctx, tdata->cpu_id);
		    tdata->trancnt++;
#else
		    broken = send_rpc(tdata->epfd, buf, ctx);
#endif
		}
            } else if (evts[i].events == EPOLLIN) {
                ret = read(ctx->fd, buf, ressize);
                assert(ret > 0);
                assert(ret <= ctx->recv_left);
#ifdef VERBOSE
		tdata->total_recvd += ret;
#endif
                ctx->recv_left -= ret;
                if (ctx->recv_left > 0)
                    continue;
    
                if (ctx->msg_cnt < msgs_per_conn) {
#ifdef VERBOSE
		    broken = send_rpc(tdata->epfd, buf, ctx, tdata->cpu_id);
		    tdata->trancnt++;
#else
                    broken = send_rpc(tdata->epfd, buf, ctx);
#endif
                } else {
                    close(ctx->fd);
                    conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx);
                }
            } else
                assert(0);

            if (broken) {
                close(ctx->fd);
                conn_client(tdata->destip, tdata->destport, tdata->srcip, tdata->epfd, ctx);
            }
        }
    }

    return NULL;
}
/*-------------------------------------------------------------------------------------------------------*/
void
conn_client(struct in_addr destip, uint16_t destport, struct in_addr srcip, 
        int epfd, struct conn_context *ctx) {
    int skt;
    int reuse;
    struct linger linger;
    struct sockaddr_in destaddr, srcaddr;
    socklen_t daddrlen = sizeof(destaddr), saddrlen = sizeof(srcaddr);
    struct epoll_event evt;
    int status;

    /* Open the socket */
    if((skt = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1) {
        perror("Unable to open socket");
        exit_cleanup();
    }

    /* Allow quick reuse of outgoing ports */
    reuse = 1;
    if(setsockopt(skt, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ==
            -1) {
        perror("Unable to set socket options");
        exit_cleanup();
    }
    linger.l_onoff = 1;
    linger.l_linger = 0;
    if(setsockopt(skt, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) == -1) {
        perror("Unable to set socket linger option");
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
    if(bind(skt, (struct sockaddr *)&srcaddr, saddrlen) == -1) {
        perror("Unable to bind");
        exit_cleanup();
    }

    ctx->fd = skt;
    ctx->msg_cnt = 0;
    ctx->send_left = reqsize;
    
    /* Add the socket to epoll */
    evt.events = EPOLLOUT | EPOLLHUP | EPOLLERR;
    evt.data.ptr = ctx;

    if(epoll_ctl(epfd, EPOLL_CTL_ADD, skt, &evt) != 0) {
        perror("Unable to add socket to epoll");
        exit_cleanup();
    }

    status = connect(skt, (struct sockaddr *)&destaddr, daddrlen);

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
