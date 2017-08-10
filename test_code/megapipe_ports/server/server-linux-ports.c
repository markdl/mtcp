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
/* For fcntl */
#include <fcntl.h>

#include "server-linux-ports.h"

/* Global - per-thread data */
struct threaddata tdata[MAX_THREADS];

int num_threads = MAX_THREADS;

int get_num_cpus()
{
        return sysconf(_SC_NPROCESSORS_ONLN);
}

int bind_cpu(int cpu)
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

int main(int argc, char *argv[]) {
    int param_port = SERVER_PORT;
    char *param_listenip = SERVER_IP;
    struct in_addr listenip;

    printf("Usage: %s [-s] [-l] [-b <num>] [listen IP] [listen port] [# of threads]\n", 
            argv[0]);
    printf("   -s: enable listenspawn()\n");
    printf("   -l: enable lightweight socket\n");
    printf("   -b: set maximum batch size\n");

again:  /* I know goto considered harmful. Forgive me. */
    if (argc >= 2 && strcmp(argv[1], "-s") == 0) {
        argv++;
        argc--;
        goto again;
    }

    if (argc >= 2 && strcmp(argv[1], "-l") == 0) {
        argv++;
        argc--;
        goto again;
    }

    if (argc >= 3 && strcmp(argv[1], "-b") == 0) {
        argv += 2;
        argc -= 2;
        goto again;
    }

    if (argc >= 3) {
        param_listenip = argv[1];
        sscanf(argv[2], "%d", &param_port);
    }

    if (argc == 4) {
        sscanf(argv[3], "%d", &num_threads);
    }

    assert(num_threads >= 1 && num_threads <= get_num_cpus());

    if(inet_aton(param_listenip, &listenip) == 0) {
        fprintf(stderr, "Invalid listen IP\n");
        exit_cleanup();
    }

    printf("# of threads: %d\n", num_threads);

    mask_signal();
    init_threads(listenip, param_port);
    init_timer();
    do_stats();

    return EXIT_SUCCESS;
}

void mask_signal(void) {
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

void init_timer(void) {
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

int init_server(struct in_addr ip, uint16_t port) {
    struct linger linger;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int serverfd;

    /* Open the socket */
    if((serverfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1) {
        perror("Unable to open socket");
        exit_cleanup();
    }

#if REUSEPORT
    int port_reuse = 1;
    if(setsockopt(serverfd, SOL_SOCKET, SO_REUSEPORT, &port_reuse, sizeof(port_reuse)) == -1) {
        perror( "secksockopt() with SO_REUSEPORT failed");
        return -1;
    }
#endif

    /* Close connections quickly (RST instead of FIN) */
    linger.l_onoff = 1;
    linger.l_linger = 0;
    if(setsockopt(serverfd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) ==
            -1) {
        perror("Unable to set socket linger option");
        exit_cleanup();
    }

    /* Configure address parameters for binding */
    memset(&addr, 0, addrlen);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = ip;

    /* Bind the socket */
    if(bind(serverfd, (struct sockaddr *)&addr, addrlen) == -1) {
        perror("Unable to bind socket");
        exit_cleanup();
    }

    /* Start listening for client connections */
    if(listen(serverfd, 256) != 0) {
        perror("Cannot listen for client connections");
        exit_cleanup();
    }

    return serverfd;
}

void init_threads(struct in_addr destip, int destport) 
{
    int i;

    for(i = 0; i < num_threads; i++) {
        tdata[i].trancnt = 0;
        tdata[i].cpu_id = i;
        memcpy(&tdata[i].destip, &destip, sizeof(struct in_addr));
        tdata[i].destport = destport; 
        
        if(pthread_create(&(tdata[i].thread), NULL, process_clients,
                    &(tdata[i])) != 0) {
            perror("Unable to create worker thread");
            exit_cleanup();
        }
    }
}

struct context_pool *init_pool(int size)
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

struct conn_context *alloc_context(struct context_pool *pool)
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

void free_context(struct context_pool *pool, struct conn_context *context)
{
    assert(pool->allocated > 0);
    pool->allocated--;

    context->next_idx = pool->next_idx;
    pool->next_idx = context - pool->arr;
}

void *process_clients(void *arg) 
{
    struct threaddata *mydata = (struct threaddata *)arg;
    struct context_pool *pool;
    cpu_set_t cpu_mask;
    int ret;

    /* Added variables for BSD socket */
    int listener, ep, nevents, i;
    int sockid = -1;
    struct epoll_event ev, *events;

    bind_cpu(mydata->cpu_id);

    pool = init_pool(MAX_CONNS_PER_THREAD);

    if(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &ret) != 0) {
        perror("Unable to set thread cancellation type");
        exit_cleanup();
    }

    assert(ret == 0);

    CPU_ZERO(&cpu_mask);
    CPU_SET(mydata->cpu_id, &cpu_mask);
#if REUSEPORT
    listener = init_server(mydata->destip, mydata->destport);
#else
    mydata->destport += mydata->cpu_id;
    listener = init_server(mydata->destip, mydata->destport);
#endif
    printf("Listening address: %s:%d, socket %d\n", inet_ntoa(mydata->destip), mydata->destport, listener);
    
    ret = fcntl(listener, F_SETFL, O_NONBLOCK);
    assert(ret==0);
    
    ep = epoll_create(MAX_EVENTS);
    if(ret < 0){
        perror("epoll_create");
        exit_cleanup();
    }
    events = (struct epoll_event *)calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if(!events){
        perror("failed to allocate events");
        exit_cleanup();
    }

    ev.events = EPOLLIN;
    ev.data.fd = listener;
    epoll_ctl(ep, EPOLL_CTL_ADD, listener, &ev);

    while(1) {
        struct conn_context *context;
        nevents = epoll_wait(ep, events, MAX_EVENTS, -1);

        if(nevents < 0){
            perror("epoll_wait");
            exit_cleanup();
        }

        for(i = 0; i < nevents; i++){
            if(events[i].data.fd == listener){
                /* Accept */
                while(1){
                    sockid = accept(listener, NULL, NULL);
                    if (sockid >= 0){
                        ret = fcntl(sockid, F_SETFL, O_NONBLOCK);
                        if(ret == -1){
                            perror("fcntl");
                            exit_cleanup();
                        }
                        ev.events = EPOLLIN;
                        context = alloc_context(pool);
                        context->fd = sockid;
                        context->recv_left = context->send_left = 0;
                        ev.data.ptr = context;
                        epoll_ctl(ep, EPOLL_CTL_ADD, sockid, &ev);
                    } else {
                        if(errno!=EAGAIN){
                            perror("accept()");
                            exit_cleanup();
                        }
                        break;
                    }
                }
            } else if (events[i].events & (EPOLLHUP | EPOLLERR)){
                /* Close */
                context = events[i].data.ptr;
                close(context->fd);
                free_context(pool, context);
            } else if (events[i].events & EPOLLIN) {
                int reqsize, ressize;
                context = events[i].data.ptr;
                /* Read */
                while ((ret = read(context->fd, context->buf, MAX_BUFSIZE)) > 0) {
                    if(context->recv_left == 0  && context->send_left == 0){
                        reqsize = *((int *)context->buf);
                        ressize = *((int *)(context->buf + 4));
                        context->recv_left = reqsize - ret;
                        context->send_left = ressize;
                    } else {
                        assert(ret <= context->recv_left);
                        context->recv_left -= ret;
                    }
                    if(context->recv_left == 0){
                        break;
                    }
                }
                
                /* CLOSE/RESET */
                if (ret == 0) {
                    epoll_ctl(ep, EPOLL_CTL_DEL, context->fd, 0);
                    close(context->fd);
                    free_context(pool, context);
                } else if (ret < 0 && errno != EAGAIN) {
                    perror("read()");
                    close(context->fd);
                    free_context(pool, context);
                }

                /* Write */
                if (context->recv_left == 0 && context->send_left > 0) {
                    while(context->send_left > 0){
                        ret = write(context->fd, context->buf, context->send_left);
                        context->send_left -= ret;
                    }

                    if (ret != -1){
                        mydata->trancnt += 1;
                    } else {
                        perror("write failed");
                        exit_cleanup();
                    }
                }
            }
        }
    }
        
    return NULL;
}

void do_stats(void) {
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
            }
            fprintf(stderr, "\tTotal %8lu\n", trancnt);

        } else if(signum == SIGINT) {
            printf("\nExiting...\n");
            stop_threads();
            break;
        }
    }
}

void exit_cleanup(void) {
    stop_threads();
    exit(EXIT_FAILURE);
}

void stop_threads(void) {
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
