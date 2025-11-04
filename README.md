# elkssl - TLS 1.2 Library for ELKS

A lightweight SSL/TLS 1.2 implementation for the ELKS (Embeddable Linux Kernel Subset) 16-bit environment, derived from Mbed TLS 2.29.

## Quick Start

```bash
# Build the library
source ../env.sh
./build-elks-elkssl.sh

# Output: build-elks/lib/elkssl.lib (~322 KB)
```

## Features

- ✅ TLS 1.2 client mode
- ✅ RSA key exchange (PKCS#1 v1.5)
- ✅ AES-128-CBC encryption
- ✅ SHA-1, SHA-256, MD5 hashing
- ✅ X.509 certificate parsing/validation
- ✅ PEM/DER format support
- ✅ Optimized for 16-bit architecture
- ✅ ~2KB SSL buffers (configurable)

## Documentation

- **[API.md](API.md)** - Complete API reference with examples
- **[BUILD.md](BUILD.md)** - Build instructions and integration guide

## Requirements

- ELKS development environment
- OpenWatcom C compiler 1.9+
- Large memory model (recommended)
- 12-16 KB RAM per TLS connection
- 8+ KB stack space

## Basic Usage

```c
#include "ssl.h"
#include "entropy.h"
#include "ctr_drbg.h"

mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

/* Initialize and configure */
mbedtls_ssl_init(&ssl);
mbedtls_ssl_config_init(&conf);
mbedtls_entropy_init(&entropy);
mbedtls_ctr_drbg_init(&ctr_drbg);

/* Seed RNG */
mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

/* Configure SSL */
mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                            MBEDTLS_SSL_TRANSPORT_STREAM,
                            MBEDTLS_SSL_PRESET_DEFAULT);
mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

/* Setup and connect */
mbedtls_ssl_setup(&ssl, &conf);
mbedtls_ssl_set_hostname(&ssl, "example.com");
mbedtls_ssl_set_bio(&ssl, &sockfd, net_send, net_recv, NULL);

/* Handshake */
mbedtls_ssl_handshake(&ssl);

/* Send/receive */
mbedtls_ssl_write(&ssl, data, len);
mbedtls_ssl_read(&ssl, buffer, bufsize);

/* Cleanup */
mbedtls_ssl_free(&ssl);
```

## File Structure

```
Macssl-elks/
├── README.md              # This file
├── API.md                 # Complete API documentation
├── BUILD.md               # Build and integration guide
├── build-elks-elkssl.sh   # Build script
├── Project/               # Source code
│   ├── *.c               # Implementation files (36 files)
│   ├── *.h               # Header files
│   └── config.h          # Configuration options
└── build-elks/           # Build output (created during build)
    ├── lib/
    │   └── elkssl.lib    # Static library
    └── include/          # Exported headers
```

## Configuration

Edit `Project/config.h` to customize:

```c
/* Memory limits */
#define MBEDTLS_SSL_MAX_CONTENT_LEN 2048  /* SSL record buffer */
#define MBEDTLS_MPI_MAX_SIZE 256          /* Max RSA key size */

/* Protocol support */
#define MBEDTLS_SSL_PROTO_TLS1_2          /* TLS 1.2 only */
#define MBEDTLS_SSL_CLI_C                 /* Client mode */

/* Crypto algorithms */
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED  /* RSA key exchange */
#define MBEDTLS_AES_C                     /* AES encryption */
#define MBEDTLS_SHA256_C                  /* SHA-256 hashing */
```

## Limitations

- **Client only** - No TLS server mode
- **No ECC** - RSA only (no ECDHE/ECDSA)
- **No file I/O** - Load certificates into memory
- **16-bit constraints** - No 64-bit arithmetic
- **Single-threaded** - Not thread-safe

## Security Notes

⚠️ **Important**: The default entropy source in `Project/entropy_elks.c` returns dummy data. Replace `mbedtls_hardware_poll()` with a real hardware entropy source before production use.

## Building Applications

### Makefile Example

```makefile
ELKSSL = ../../Macssl-elks
CFLAGS += -I$(ELKSSL)/build-elks/include
LDFLAGS += $(ELKSSL)/build-elks/lib/elkssl.lib

myapp: myapp.o
$(LD) $(LDFLAGS) -o myapp myapp.o
```

See [BUILD.md](BUILD.md) for complete integration instructions.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Stack overflow | Increase stack size or reduce `MBEDTLS_SSL_MAX_CONTENT_LEN` |
| Memory allocation fails | Increase heap or reduce buffer sizes in config.h |
| Handshake fails | Enable debug output, check certificates, verify cipher suites |
| Build errors | Verify OpenWatcom installed, source `env.sh` |

## Version

Based on Mbed TLS 2.29, adapted for ELKS 16-bit environment.

## See Also

- [API Documentation](API.md) - Full API reference
- [Build Guide](BUILD.md) - Integration and troubleshooting
- ELKS Project: https://github.com/jbruchon/elks
