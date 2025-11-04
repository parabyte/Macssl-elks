# elkssl API Documentation

## Overview

elkssl is a lightweight TLS 1.2 library for ELKS (Embeddable Linux Kernel Subset), derived from Mbed TLS 2.29. It provides secure network communication capabilities in the constrained 16-bit ELKS environment.

**Supported Features:**
- TLS 1.2 client
- RSA key exchange (PKCS#1 v1.5)
- AES-128-CBC encryption
- SHA-1, SHA-256, MD5 hash algorithms
- X.509 certificate parsing and validation
- PEM/DER format support

**Not Supported:**
- TLS server mode (client only)
- Elliptic Curve Cryptography (ECC)
- TLS 1.3
- Hardware acceleration
- Threading/multi-context use

---

## Memory Requirements

- **Library size**: ~322 KB
- **Memory model**: Large (far pointers)
- **SSL buffers**: 2 KB (configurable in config.h)
- **Stack usage**: ~4-8 KB per connection (estimate)

---

## Core Data Structures

### SSL Context
```c
typedef struct mbedtls_ssl_context mbedtls_ssl_context;
typedef struct mbedtls_ssl_config mbedtls_ssl_config;
```
Main structures for managing TLS connections.

### X.509 Certificate
```c
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
```
Represents a parsed X.509 certificate chain.

### RSA Context
```c
typedef struct mbedtls_rsa_context mbedtls_rsa_context;
```
RSA public/private key context.

### Entropy & RNG
```c
typedef struct mbedtls_entropy_context mbedtls_entropy_context;
typedef struct mbedtls_ctr_drbg_context mbedtls_ctr_drbg_context;
```
Random number generation based on CTR-DRBG with entropy sources.

---

## API Reference

### 1. SSL/TLS Functions

#### Initialize SSL Configuration
```c
void mbedtls_ssl_config_init(mbedtls_ssl_config *conf);
int mbedtls_ssl_config_defaults(mbedtls_ssl_config *conf,
                                 int endpoint,
                                 int transport,
                                 int preset);
```
**Parameters:**
- `endpoint`: `MBEDTLS_SSL_IS_CLIENT` or `MBEDTLS_SSL_IS_SERVER`
- `transport`: `MBEDTLS_SSL_TRANSPORT_STREAM` (TCP) or `MBEDTLS_SSL_TRANSPORT_DATAGRAM` (UDP/DTLS)
- `preset`: `MBEDTLS_SSL_PRESET_DEFAULT`

**Example:**
```c
mbedtls_ssl_config conf;
mbedtls_ssl_config_init(&conf);
mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                            MBEDTLS_SSL_TRANSPORT_STREAM,
                            MBEDTLS_SSL_PRESET_DEFAULT);
```

#### Set Authentication Mode
```c
void mbedtls_ssl_conf_authmode(mbedtls_ssl_config *conf, int authmode);
```
**Parameters:**
- `MBEDTLS_SSL_VERIFY_NONE`: No certificate verification
- `MBEDTLS_SSL_VERIFY_OPTIONAL`: Verify if certificate provided
- `MBEDTLS_SSL_VERIFY_REQUIRED`: Certificate required and verified

#### Configure Certificate Authority
```c
void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config *conf,
                                mbedtls_x509_crt *ca_chain,
                                mbedtls_x509_crl *ca_crl);
```

#### Configure RNG
```c
void mbedtls_ssl_conf_rng(mbedtls_ssl_config *conf,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng);
```

#### Initialize SSL Context
```c
void mbedtls_ssl_init(mbedtls_ssl_context *ssl);
int mbedtls_ssl_setup(mbedtls_ssl_context *ssl,
                      const mbedtls_ssl_config *conf);
```

#### Set Hostname (SNI)
```c
int mbedtls_ssl_set_hostname(mbedtls_ssl_context *ssl,
                              const char *hostname);
```

#### Set I/O Functions
```c
void mbedtls_ssl_set_bio(mbedtls_ssl_context *ssl,
                         void *p_bio,
                         int (*f_send)(void *, const unsigned char *, size_t),
                         int (*f_recv)(void *, unsigned char *, size_t),
                         int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t));
```

#### Perform Handshake
```c
int mbedtls_ssl_handshake(mbedtls_ssl_context *ssl);
```
**Returns:**
- `0` on success
- `MBEDTLS_ERR_SSL_WANT_READ` or `MBEDTLS_ERR_SSL_WANT_WRITE` if non-blocking I/O needs retry
- Negative error code on failure

#### Read Data
```c
int mbedtls_ssl_read(mbedtls_ssl_context *ssl,
                     unsigned char *buf,
                     size_t len);
```
**Returns:** Number of bytes read, or error code

#### Write Data
```c
int mbedtls_ssl_write(mbedtls_ssl_context *ssl,
                      const unsigned char *buf,
                      size_t len);
```
**Returns:** Number of bytes written, or error code

#### Close Connection
```c
int mbedtls_ssl_close_notify(mbedtls_ssl_context *ssl);
```

#### Cleanup
```c
void mbedtls_ssl_free(mbedtls_ssl_context *ssl);
void mbedtls_ssl_config_free(mbedtls_ssl_config *conf);
```

---

### 2. X.509 Certificate Functions

#### Initialize Certificate
```c
void mbedtls_x509_crt_init(mbedtls_x509_crt *crt);
```

#### Parse Certificate (PEM/DER)
```c
int mbedtls_x509_crt_parse(mbedtls_x509_crt *chain,
                           const unsigned char *buf,
                           size_t buflen);
```

#### Parse Certificate File
```c
int mbedtls_x509_crt_parse_file(mbedtls_x509_crt *chain,
                                const char *path);
```
**Note:** File I/O is disabled in ELKS build (`MBEDTLS_FS_IO` undefined). Use `mbedtls_x509_crt_parse` with data loaded in memory instead.

#### Get Certificate Info
```c
int mbedtls_x509_crt_info(char *buf, size_t size,
                          const char *prefix,
                          const mbedtls_x509_crt *crt);
```

#### Verify Certificate
```c
int mbedtls_x509_crt_verify(mbedtls_x509_crt *crt,
                            mbedtls_x509_crt *trust_ca,
                            mbedtls_x509_crl *ca_crl,
                            const char *cn,
                            uint32_t *flags,
                            int (*f_vrfy)(void *, mbedtls_x509_crt *, int, uint32_t *),
                            void *p_vrfy);
```

#### Cleanup
```c
void mbedtls_x509_crt_free(mbedtls_x509_crt *crt);
```

---

### 3. Entropy and Random Number Generation

#### Initialize Entropy
```c
void mbedtls_entropy_init(mbedtls_entropy_context *ctx);
```

#### Initialize CTR-DRBG
```c
void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context *ctx);
int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context *ctx,
                          int (*f_entropy)(void *, unsigned char *, size_t),
                          void *p_entropy,
                          const unsigned char *custom,
                          size_t len);
```

**Example:**
```c
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
const char *pers = "my_app";

mbedtls_entropy_init(&entropy);
mbedtls_ctr_drbg_init(&ctr_drbg);
mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                      (const unsigned char *)pers, strlen(pers));
```

#### Generate Random Bytes
```c
int mbedtls_ctr_drbg_random(void *p_rng,
                            unsigned char *output,
                            size_t output_len);
```

#### Cleanup
```c
void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context *ctx);
void mbedtls_entropy_free(mbedtls_entropy_context *ctx);
```

**Important:** The default `mbedtls_hardware_poll` in `entropy_elks.c` returns dummy data. Replace with real entropy source for production use.

---

### 4. Cryptographic Primitives

#### AES Encryption/Decryption
```c
void mbedtls_aes_init(mbedtls_aes_context *ctx);
int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx,
                           const unsigned char *key,
                           unsigned int keybits);
int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx,
                           const unsigned char *key,
                           unsigned int keybits);
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output);
void mbedtls_aes_free(mbedtls_aes_context *ctx);
```

#### SHA-256 Hashing
```c
void mbedtls_sha256_init(mbedtls_sha256_context *ctx);
int mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224);
int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen);
int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char output[32]);
void mbedtls_sha256_free(mbedtls_sha256_context *ctx);

/* One-shot hash */
int mbedtls_sha256(const unsigned char *input,
                   size_t ilen,
                   unsigned char output[32],
                   int is224);
```

#### SHA-1 Hashing
```c
void mbedtls_sha1_init(mbedtls_sha1_context *ctx);
int mbedtls_sha1_starts(mbedtls_sha1_context *ctx);
int mbedtls_sha1_update(mbedtls_sha1_context *ctx,
                        const unsigned char *input,
                        size_t ilen);
int mbedtls_sha1_finish(mbedtls_sha1_context *ctx,
                        unsigned char output[20]);
void mbedtls_sha1_free(mbedtls_sha1_context *ctx);

/* One-shot hash */
int mbedtls_sha1(const unsigned char *input,
                 size_t ilen,
                 unsigned char output[20]);
```

#### RSA Operations
```c
void mbedtls_rsa_init(mbedtls_rsa_context *ctx);
int mbedtls_rsa_pkcs1_encrypt(mbedtls_rsa_context *ctx,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng,
                              size_t ilen,
                              const unsigned char *input,
                              unsigned char *output);
int mbedtls_rsa_pkcs1_decrypt(mbedtls_rsa_context *ctx,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng,
                              size_t *olen,
                              const unsigned char *input,
                              unsigned char *output,
                              size_t output_max_len);
void mbedtls_rsa_free(mbedtls_rsa_context *ctx);
```

---

### 5. Error Handling

#### Get Error String
```c
void mbedtls_strerror(int errnum, char *buffer, size_t buflen);
```

**Example:**
```c
char error_buf[100];
int ret = mbedtls_ssl_handshake(&ssl);
if (ret != 0) {
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    printf("Error: %s\n", error_buf);
}
```

#### Common Error Codes
- `MBEDTLS_ERR_SSL_WANT_READ`: Non-blocking read would block
- `MBEDTLS_ERR_SSL_WANT_WRITE`: Non-blocking write would block
- `MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY`: Peer closed connection
- `MBEDTLS_ERR_NET_CONN_RESET`: Connection reset by peer
- `MBEDTLS_ERR_X509_CERT_VERIFY_FAILED`: Certificate verification failed

---

### 6. Debugging

#### Enable Debug Output
```c
void mbedtls_ssl_conf_dbg(mbedtls_ssl_config *conf,
                          void (*f_dbg)(void *, int, const char *, int, const char *),
                          void *p_dbg);
void mbedtls_debug_set_threshold(int threshold);
```

**Debug levels:**
- `0`: No debug
- `1`: Error
- `2`: State change
- `3`: Informational
- `4`: Verbose

**Example:**
```c
void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    printf("%s:%04d: %s", file, line, str);
}

mbedtls_debug_set_threshold(2);
mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
```

---

## Complete TLS Client Example

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ssl.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "x509_crt.h"
#include "error.h"

/* Socket I/O wrapper functions (implement based on your socket API) */
int my_send(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int*)ctx;
    /* return send(fd, buf, len, 0); */
    return -1; /* Placeholder */
}

int my_recv(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int*)ctx;
    /* return recv(fd, buf, len, 0); */
    return -1; /* Placeholder */
}

int main(void) {
    int ret, sockfd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    const char *pers = "ssl_client";
    char buf[512];

    /* 1. Initialize structures */
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    /* 2. Seed RNG */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("mbedtls_ctr_drbg_seed failed: %d\n", ret);
        goto exit;
    }

    /* 3. Load CA certificate (optional, for verification) */
    /* ret = mbedtls_x509_crt_parse(&cacert, ca_cert_pem, strlen(ca_cert_pem) + 1); */

    /* 4. Setup SSL/TLS configuration */
    ret = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("mbedtls_ssl_config_defaults failed: %d\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    /* mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL); */
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /* 5. Setup SSL context */
    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        printf("mbedtls_ssl_setup failed: %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ssl_set_hostname(&ssl, "example.com");
    if (ret != 0) {
        printf("mbedtls_ssl_set_hostname failed: %d\n", ret);
        goto exit;
    }

    /* 6. Connect socket (implement socket connection here) */
    /* sockfd = connect_to_host("example.com", 443); */

    /* 7. Setup I/O callbacks */
    mbedtls_ssl_set_bio(&ssl, &sockfd, my_send, my_recv, NULL);

    /* 8. Perform TLS handshake */
    printf("Performing SSL/TLS handshake...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && 
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("mbedtls_ssl_handshake failed: -0x%x\n", -ret);
            goto exit;
        }
    }
    printf("Handshake successful!\n");

    /* 9. Send HTTP request */
    const char *request = "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n";
    while ((ret = mbedtls_ssl_write(&ssl, 
            (unsigned char *)request, strlen(request))) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && 
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("mbedtls_ssl_write failed: %d\n", ret);
            goto exit;
        }
    }
    printf("Sent %d bytes\n", ret);

    /* 10. Read response */
    do {
        ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, sizeof(buf) - 1);
        if (ret > 0) {
            buf[ret] = '\0';
            printf("%s", buf);
        }
    } while (ret > 0 || ret == MBEDTLS_ERR_SSL_WANT_READ);

    /* 11. Close connection */
    mbedtls_ssl_close_notify(&ssl);

exit:
    /* 12. Cleanup */
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    /* close(sockfd); */

    return ret;
}
```

---

## Configuration Reference

Key configuration options in `Project/config.h`:

### Memory Limits
```c
#define MBEDTLS_SSL_MAX_CONTENT_LEN 2048  /* SSL record size */
#define MBEDTLS_MPI_MAX_SIZE 256          /* Max bignum size */
```

### Enabled Features
```c
#define MBEDTLS_SSL_CLI_C              /* TLS client */
#define MBEDTLS_SSL_PROTO_TLS1_2       /* TLS 1.2 */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_AES_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_X509_CRT_PARSE_C
```

### Platform Integration
```c
#define MBEDTLS_PLATFORM_CALLOC_MACRO calloc
#define MBEDTLS_PLATFORM_FREE_MACRO free
#define MBEDTLS_PLATFORM_PRINTF_MACRO printf
```

---

## Limitations & Notes

1. **16-bit Architecture**: All pointers are far pointers in large memory model. Be mindful of pointer arithmetic and casts.

2. **No File I/O**: `MBEDTLS_FS_IO` is disabled. Load certificates into memory before parsing.

3. **Stack Usage**: TLS operations require significant stack space. Ensure adequate stack size (8KB+ recommended).

4. **Entropy Source**: Replace `mbedtls_hardware_poll()` in `entropy_elks.c` with a real hardware entropy source for production.

5. **Thread Safety**: Not thread-safe. Use separate contexts per connection if implementing concurrency.

6. **Memory Allocation**: Uses standard `calloc`/`free`. Monitor heap fragmentation in long-running applications.

7. **Cipher Suites**: Limited to RSA key exchange with AES-CBC. No perfect forward secrecy (no DHE/ECDHE).

---

## Troubleshooting

### Handshake Fails
- Check certificate format (PEM vs DER)
- Verify CA chain is complete
- Enable debug output to see TLS alerts
- Check cipher suite compatibility with server

### Memory Errors
- Increase heap size in ELKS configuration
- Reduce `MBEDTLS_SSL_MAX_CONTENT_LEN`
- Check for memory leaks (missing `_free()` calls)

### Stack Overflow
- Increase stack size for process
- Reduce recursion depth in certificate chains
- Use smaller buffer sizes

---

## Additional Resources

- Mbed TLS upstream documentation: https://mbed-tls.readthedocs.io/
- TLS 1.2 RFC: https://www.rfc-editor.org/rfc/rfc5246
- X.509 RFC: https://www.rfc-editor.org/rfc/rfc5280
