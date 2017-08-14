#ifndef SERVER_H
#define SERVER_H

/* Macros */
#define SERVER_IP               "127.0.0.1"
#define SERVER_PORT             8080
#define MAX_THREADS             8
#define MAX_CONNS_PER_THREAD    500000
#define MAX_BUFSIZE        65536
#define MAX_EVENTS MAX_CONNS_PER_THREAD * 4
#define REUSEPORT 1 

/* Structure Definitions */
struct threaddata {
    pthread_t thread;
    uint64_t trancnt;
    uint64_t trancnt_prev;
    int cpu_id;
    int destport;
    struct in_addr destip;
};

struct context_pool {
    int total;
    int allocated;
    int next_idx;
    struct conn_context {
        char buf[MAX_BUFSIZE];
        int fd;
        int recv_left;
        int send_left;
        int next_idx;
    } *arr;
};

/* Fuction Prototypes */
int init_server(struct in_addr ip, uint16_t port);
void mask_signal(void);
void init_timer(void);
void init_threads(struct in_addr destip, int destport);
void *process_clients(void *arg);
void do_stats(void);
void exit_cleanup(void);
void stop_threads(void);

#endif

