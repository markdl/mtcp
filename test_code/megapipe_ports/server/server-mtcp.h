#ifndef SERVER_MTCP_H
#define SERVER_MTCP_H


/* Macros */
//#define VERBOSE 1
#define SERVER_IP               "0.0.0.0"
#define SERVER_PORT             8080
#define MAX_THREADS             16
#define MAX_CONNS_PER_THREAD    16384
#define MAX_BUFSIZE             131072
#define LISTEN_BACKLOG 1024
/* Structure Definitions */
struct threaddata {
	pthread_t thread;
	uint64_t trancnt;
#ifdef VERBOSE
	uint64_t total_recvd;
	uint64_t total_sent;
#endif
	uint64_t trancnt_prev;
#ifdef VERBOSE
	uint64_t total_recvd_prev;
	uint64_t total_sent_prev;
#endif
	int cpu_id;
	struct in_addr ip;
	uint16_t port;
	mctx_t mctx;
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
void init_server();
void mask_signal(void);
void init_timer(void);
void init_threads(struct in_addr ip, uint16_t port);
void *process_clients(void *arg);
void do_stats(void);
void exit_cleanup(void);
void stop_threads(void);

#endif

