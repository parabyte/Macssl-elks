#include "MacSSL.h"

#include "ssl.h"
#include "ctr_drbg.h"
#include "entropy.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct ssl_method_st {
	int stub;
};

struct ssl_ctx_st {
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	int configured;
};

struct ssl_st {
	SSL_CTX *ctx;
	mbedtls_ssl_context ssl;
	int fd;
	int last_error;
};

static const SSL_METHOD tls_client_method = { 0 };

static int macssl_net_send(void *ctx, const unsigned char *buf, size_t len);
static int macssl_net_recv(void *ctx, unsigned char *buf, size_t len);

int SSL_library_init(void)
{
	/* mbed TLS has no global one-time init requirement for this subset. */
	return 1;
}

void SSL_load_error_strings(void)
{
	/* Not implemented: ELKS builds omit the OpenSSL error catalog. */
}

const SSL_METHOD *TLS_client_method(void)
{
	return &tls_client_method;
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
{
	static const unsigned char pers[] = "MacSSLClient";
	int ret;
	SSL_CTX *ctx;

	(void)method;

	ctx = malloc(sizeof(*ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	mbedtls_ssl_config_init(&ctx->conf);
	mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
	mbedtls_entropy_init(&ctx->entropy);

	ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
				    &ctx->entropy, pers, sizeof(pers) - 1);
	if (ret != 0)
		goto fail;

	ret = mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
					  MBEDTLS_SSL_TRANSPORT_STREAM,
					  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0)
		goto fail;

	mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
	ctx->configured = 1;
	return ctx;

fail:
	SSL_CTX_free(ctx);
	return NULL;
}

void SSL_CTX_free(SSL_CTX *ctx)
{
	if (!ctx)
		return;

	if (ctx->configured)
		mbedtls_ssl_config_free(&ctx->conf);
	mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
	mbedtls_entropy_free(&ctx->entropy);
	free(ctx);
}

SSL *SSL_new(SSL_CTX *ctx)
{
	int ret;
	SSL *ssl;

	if (!ctx)
		return NULL;

	ssl = malloc(sizeof(*ssl));
	if (!ssl)
		return NULL;

	memset(ssl, 0, sizeof(*ssl));
	ssl->ctx = ctx;
	ssl->fd = -1;
	mbedtls_ssl_init(&ssl->ssl);

	ret = mbedtls_ssl_setup(&ssl->ssl, &ctx->conf);
	if (ret != 0) {
		mbedtls_ssl_free(&ssl->ssl);
		free(ssl);
		return NULL;
	}

	return ssl;
}

void SSL_free(SSL *ssl)
{
	if (!ssl)
		return;

	mbedtls_ssl_free(&ssl->ssl);
	free(ssl);
}

void SSL_set_fd(SSL *ssl, int fd)
{
	if (!ssl)
		return;

	ssl->fd = fd;
	mbedtls_ssl_set_bio(&ssl->ssl, &ssl->fd, macssl_net_send,
			    macssl_net_recv, NULL);
}

int SSL_connect(SSL *ssl)
{
	int ret;

	if (!ssl)
		return 0;

	ret = mbedtls_ssl_handshake(&ssl->ssl);
	if (ret == 0) {
		ssl->last_error = 0;
		return 1;
	}

	ssl->last_error = ret;
	return ret;
}

int SSL_get_error(SSL *ssl, int ret)
{
	int code;

	if (!ssl)
		return SSL_ERROR_SSL;

	if (ret > 0)
		return SSL_ERROR_NONE;
	if (ret == 0 && ssl->last_error == 0)
		return SSL_ERROR_NONE;

	code = ssl->last_error;
	switch (code) {
	case MBEDTLS_ERR_SSL_WANT_READ:
		return SSL_ERROR_WANT_READ;
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return SSL_ERROR_WANT_WRITE;
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		return SSL_ERROR_ZERO_RETURN;
	case MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION:
	case MBEDTLS_ERR_SSL_VERSION_MISMATCH:
		return SSL_ERROR_PROTOCOL_VERSION;
	default:
		break;
	}

	return SSL_ERROR_SSL;
}

const char *SSL_get_cipher(const SSL *ssl)
{
	if (!ssl)
		return NULL;

	return mbedtls_ssl_get_ciphersuite(&ssl->ssl);
}

int SSL_write(SSL *ssl, const void *buf, size_t len)
{
	int ret;

	if (!ssl)
		return -1;

	ret = mbedtls_ssl_write(&ssl->ssl, (const unsigned char *)buf, len);
	if (ret >= 0) {
		ssl->last_error = 0;
		return ret;
	}

	ssl->last_error = ret;
	return -1;
}

int SSL_read(SSL *ssl, void *buf, size_t len)
{
	int ret;

	if (!ssl)
		return -1;

	ret = mbedtls_ssl_read(&ssl->ssl, (unsigned char *)buf, len);
	if (ret >= 0) {
		ssl->last_error = 0;
		return ret;
	}

	ssl->last_error = ret;
	return -1;
}

int SSL_shutdown(SSL *ssl)
{
	int ret;

	if (!ssl)
		return 0;

	ret = mbedtls_ssl_close_notify(&ssl->ssl);
	if (ret == 0) {
		ssl->last_error = 0;
		return 1;
	}

	ssl->last_error = ret;
	return -1;
}

static int macssl_net_send(void *ctx, const unsigned char *buf, size_t len)
{
	int fd = *(int *)ctx;
	int ret;

	do {
		ret = write(fd, buf, (unsigned int)len);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
#if defined(EWOULDBLOCK)
		if (errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_WRITE;
#endif
#if defined(EAGAIN) && (!defined(EWOULDBLOCK) || EAGAIN != EWOULDBLOCK)
		if (errno == EAGAIN)
			return MBEDTLS_ERR_SSL_WANT_WRITE;
#endif
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}

	return ret;
}

static int macssl_net_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = *(int *)ctx;
	int ret;

	do {
		ret = read(fd, buf, (unsigned int)len);
	} while (ret < 0 && errno == EINTR);

	if (ret == 0)
		return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;

	if (ret < 0) {
#if defined(EWOULDBLOCK)
		if (errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_READ;
#endif
#if defined(EAGAIN) && (!defined(EWOULDBLOCK) || EAGAIN != EWOULDBLOCK)
		if (errno == EAGAIN)
			return MBEDTLS_ERR_SSL_WANT_READ;
#endif
		return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
	}

	return ret;
}
