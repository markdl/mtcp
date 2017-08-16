#ifndef CLIENT_H
#define CLIENT_H

#include <mtcp_api.h>

//#define VERBOSE 1

/* Macros */
#define DEST_IP "127.0.0.1"
#define DEST_PORT 8080
#define MAX_THREADS 16

#define BUFSIZE 65536
#define EVENTS_PER_BATCH 32
#define IP_RANGE 10

/* Structure Definitions */
struct threaddata {
	pthread_t thread;
	int epfd;
	struct in_addr destip;
	uint16_t destport;
	struct in_addr srcip;
	uint64_t trancnt;
	uint64_t total_recvd;
	uint64_t total_sent;
	uint64_t trancnt_prev;
	uint64_t total_recvd_prev;
	uint64_t total_sent_prev;
	int cpu_id;
};

struct conn_context {
    int sockid;
    int msg_cnt;
    int recv_left;
    int send_left;
};

/* Function Prototypes */
void *client_thread(void *arg);
void conn_client(struct in_addr destip, uint16_t destport, struct in_addr srcip,
					  int epfd, struct conn_context *ctx, mctx_t mctx);
void conn_wait(int epfd);
void exit_cleanup(void);

#endif
