#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <sched.h>
#include <openssl/err.h>
#include <pthread.h>

#include "ssl_functions.h"

/*----------------------------------------------------------------------------*/
#ifndef USE_LINUX
static mctx_t *g_mctx;
#endif
/*----------------------------------------------------------------------------*/
static pthread_mutex_t *locks;
/*----------------------------------------------------------------------------*/
void
thread_locking(int mode, int n, const char* file, int line)
{
	if (mode & CRYPTO_LOCK)
		pthread_mutex_lock(&locks[n]);
	else
		pthread_mutex_unlock(&locks[n]);
}
/*----------------------------------------------------------------------------*/
unsigned long
thread_id()
{
	return (unsigned long) pthread_self();
}
/*----------------------------------------------------------------------------*/
void
thread_setup(int size)
{
	locks = (pthread_mutex_t *) calloc(size, sizeof(pthread_mutex_t));
	if (!locks) {
		perror("locks calloc");
		abort();
	}
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		if (pthread_mutex_init(&locks[i], NULL) != 0) {
			perror("pthread_mutex_init");
			abort();
		}
	}

	CRYPTO_set_id_callback(thread_id);
	CRYPTO_set_locking_callback(thread_locking);
}
/*----------------------------------------------------------------------------*/
void
thread_cleanup(pthread_mutex_t *locks, int size)
{
	for (int i = 0; i < size; i++) {
		pthread_mutex_destroy(&locks[i]);
	}
	free(locks);
	
	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);
}
/*----------------------------------------------------------------------------*/
void
init_openssl(int use_lock, int num_locks)
{
	OpenSSL_add_all_algorithms();
	OpenSSL_add_ssl_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	if (SSL_library_init() < 0)
		fprintf(stderr, "Could not initialize the OpenSSL library\n");
	if (use_lock)
		thread_setup(num_locks);
}
/*----------------------------------------------------------------------------*/
void
cleanup_openssl(int use_lock, int num_locks)
{
	if (use_lock)
		thread_cleanup(locks, num_locks);
	EVP_cleanup();
}
/*----------------------------------------------------------------------------*/
SSL_CTX *
#ifndef USE_LINUX
create_ssl_context(mctx_t *ctxs)
#else
create_ssl_context()
#endif
{
	const SSL_METHOD *method = SSLv23_server_method();
	
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		abort();
	}
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

#ifndef USE_LINUX
	g_mctx = ctxs;
#endif
	
	return ctx;
}
/*----------------------------------------------------------------------------*/
void
configure_ssl_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);
	
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "credentials/cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	if (SSL_CTX_use_PrivateKey_file(ctx, "credentials/key.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}
/*----------------------------------------------------------------------------*/
#ifndef USE_LINUX
int
my_sock_read(BIO *b, char *out, int outl)
{
	int ret;
	if (out != NULL) {
		int core = sched_getcpu();
		mctx_t mctx = g_mctx[core];
		errno = 0;

		ret = mtcp_read(mctx, b->num, out, outl);
		BIO_clear_retry_flags(b);
		if (ret <= 0) {
			if (BIO_sock_should_retry(ret))
				BIO_set_retry_read(b);
		}
	}
	return (ret);
}
/*----------------------------------------------------------------------------*/
int
my_sock_write(BIO *b, const char *in, int inl)
{
	int core = sched_getcpu();
	mctx_t mctx = g_mctx[core];
	errno = 0;

	int ret = mtcp_write(mctx, b->num, in, inl);
	BIO_clear_retry_flags(b);
	if (ret <= 0) {
		if (BIO_sock_should_retry(ret))
			BIO_set_retry_write(b);
	}
	return (ret);
}
#endif
/*----------------------------------------------------------------------------*/
SSL *
ssl_new_connection(SSL_CTX *ssl_ctx, int sockid)
{
	SSL *ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ssl, sockid);

#ifndef USE_LINUX
	BIO *wbio = SSL_get_wbio(ssl);
	BIO *rbio = SSL_get_rbio(ssl);
	wbio->method->bwrite = my_sock_write;
	rbio->method->bread = my_sock_read;
	BIO_set_nbio(wbio, 1);
	BIO_set_nbio(rbio, 1);
	SSL_set_bio(ssl, rbio, wbio);
#endif

	return ssl;
}
