#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#if 0
static int my_sock_read(BIO *b, char *out, int outl)
{
	int ret = 0;

	if (out != NULL) {
		errno = 0;
		//ret = readsocket(b->num, out, outl);
		ret = read(b->num, out, outl);
		BIO_clear_retry_flags(b);
		if (ret <= 0) {
			if (BIO_sock_should_retry(ret))
				BIO_set_retry_read(b);
		}
	}
	return (ret);
}

static int my_sock_write(BIO *b, const char *in, int inl)
{
	int ret;

	errno = 0;
	//ret = writesocket(b->num, in, inl);
	//	ret = write(STDOUT_FILENO, in, inl);
	ret = write(b->num, in, inl);
	BIO_clear_retry_flags(b);
	if (ret <= 0) {
		if (BIO_sock_should_retry(ret))
			BIO_set_retry_write(b);
	}
	return (ret);
}
#endif

int create_socket(int port)
{
   int s;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		perror("Unable to create socket");
	 exit(EXIT_FAILURE);
	}
	
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}
	
	if (listen(s, 1) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}
	
	return s;
}

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	
	method = SSLv23_server_method();
	
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	return ctx;
}

void configure_context(SSL_CTX *ctx)
{
	SSL_CTX_set_ecdh_auto(ctx, 1);
	
	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	init_openssl();
	SSL_CTX *ctx = create_context();
  
	configure_context(ctx);

	int sock = create_socket(4433);

	/* Handle connections */
	while(1) {
		struct sockaddr_in addr;
		uint len = sizeof(addr);
		SSL *ssl;
		const char reply[] = "test\n";
	   unsigned long size = strlen(reply);
		
		int client = accept(sock, (struct sockaddr*)&addr, &len);
		if (client < 0) {
			perror("Unable to accept");
			exit(EXIT_FAILURE);
		}

		/* Create SSL object for each connection, and associate the connection with the object using SSL_set_fd (or SSL_set_bio) */
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, client);
		/*
		BIO *wbio = SSL_get_wbio(ssl);
		BIO *rbio = SSL_get_rbio(ssl);
		wbio->method->bwrite = my_sock_write;
		rbio->method->bread = my_sock_read;
		SSL_set_bio(ssl, rbio, wbio);
		*/
		
		/* TLS/SSL handshake performed with SSL_accept or SSL_connect */
		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			/* SSL_write and SSL_read used to read nad write data on the TLS/SSL connection */
			SSL_write(ssl, reply, size);
		}

		SSL_free(ssl);
		close(client);
	}

	close(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}
