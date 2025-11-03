#ifndef MACSSL_H
#define MACSSL_H

#include <stddef.h>

/* Minimal OpenSSL-style compatibility layer backed by elkssl (mbed TLS). */

typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

/* Error codes mimicking the OpenSSL API. */
#define SSL_ERROR_NONE              0
#define SSL_ERROR_SSL               1
#define SSL_ERROR_WANT_READ         2
#define SSL_ERROR_WANT_WRITE        3
#define SSL_ERROR_SYSCALL           5
#define SSL_ERROR_ZERO_RETURN       6
#define SSL_ERROR_WANT_CONNECT      7
#define SSL_ERROR_PROTOCOL_VERSION  8

int SSL_library_init(void);
void SSL_load_error_strings(void);

const SSL_METHOD *TLS_client_method(void);

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void SSL_CTX_free(SSL_CTX *ctx);

SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);

void SSL_set_fd(SSL *ssl, int fd);

int SSL_connect(SSL *ssl);
int SSL_get_error(SSL *ssl, int ret);

const char *SSL_get_cipher(const SSL *ssl);

int SSL_write(SSL *ssl, const void *buf, size_t len);
int SSL_read(SSL *ssl, void *buf, size_t len);

int SSL_shutdown(SSL *ssl);

#endif /* MACSSL_H */

