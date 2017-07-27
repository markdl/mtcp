#include <openssl/ssl.h>

void thread_locking(int mode, int n, const char* file, int line);
unsigned long thread_id();
void thread_setup(int size);
void thread_cleanup(pthread_mutex_t *locks, int size);
void init_openssl(int use_lock, int num_locks);
void cleanup_openssl(int use_lock, int num_locks);
void configure_ssl_context(SSL_CTX *ctx);
#ifdef USE_LINUX
SSL_CTX * create_ssl_context();
#else
#include <mtcp_api.h>
SSL_CTX * create_ssl_context(mctx_t *mctx);
int my_sock_read(BIO *b, char *out, int outl);
int my_sock_write(BIO *b, const char *in, int inl);
#endif
SSL * ssl_new_connection(SSL_CTX *ssl_ctx, int sockid);
