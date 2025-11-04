# elkssl Build Guide for ELKS

## Overview

This guide explains how to build and integrate the elkssl library (TLS 1.2 for ELKS) into your ELKS applications.

---

## Prerequisites

### 1. ELKS Development Environment

You must have a working ELKS build environment with:
- ELKS kernel source tree
- OpenWatcom C compiler (version 1.9 or later)
- ELKS cross-compilation toolchain

**Verify your setup:**
```bash
# Check ELKS environment
source /path/to/elks/env.sh
echo $TOPDIR        # Should point to ELKS root
echo $WATCOM        # Should point to OpenWatcom installation

# Verify OpenWatcom compiler
wcc -?
wlib -?
```

### 2. Directory Structure

elkssl should be located at:
```
$TOPDIR/Macssl-elks/
├── build-elks-elkssl.sh    # Build script
├── Project/                # Source files
│   ├── *.c                 # Implementation files
│   ├── *.h                 # Header files
│   └── config.h            # Configuration
└── build-elks/             # Build output (created during build)
    ├── lib/
    │   └── elkssl.lib      # Static library
    └── include/            # Exported headers
```

---

## Building elkssl Library

### Basic Build

```bash
cd $TOPDIR/Macssl-elks
source ../env.sh
./build-elks-elkssl.sh
```

**Expected output:**
```
Created /path/to/elks/Macssl-elks/build-elks/lib/elkssl.lib
```

### Clean Build

```bash
./build-elks-elkssl.sh clean
./build-elks-elkssl.sh
```

### Build Process Details

The build script performs these steps:

1. **Reads memory model** from `$TOPDIR/libc/watcom.model`
   - Default: Large model (`-ml`)
   - Supports: Small (`-ms`), Medium (`-mm`), Compact (`-mc`), Large (`-ml`)

2. **Compiles source files** with OpenWatcom `wcc`:
   ```
   -os          # Optimize for space
   -bt=none     # No target system
   -0           # 8086 instructions
   -zq          # Quiet mode
   -s           # Remove stack overflow checks
   -ml          # Large memory model
   -wx          # Maximum warnings
   -zastd=c99   # C99 standard
   -zls         # Remove default library references
   ```

3. **Creates static library** with `wlib`:
   ```
   wlib -q -b -n elkssl.lib
   wlib -q elkssl.lib +file1.obj +file2.obj ...
   ```

4. **Exports headers** to `build-elks/include/`

5. **Cleans up** intermediate `.obj` and `.err` files

### Verify Build

```bash
ls -lh build-elks/lib/elkssl.lib
# Should show ~322 KB file

ls build-elks/include/*.h | wc -l
# Should show exported headers
```

---

## Integrating elkssl into Your Application

### Method 1: Makefile Integration (Recommended)

For applications in the ELKS tree (`elkscmd/`):

**Example Makefile:**
```makefile
# elkscmd/myapp/Makefile

BASEDIR = ../..
include $(BASEDIR)/Make.defs

ELKSSL_DIR = $(TOPDIR)/Macssl-elks
ELKSSL_LIB = $(ELKSSL_DIR)/build-elks/lib/elkssl.lib
ELKSSL_INC = $(ELKSSL_DIR)/build-elks/include

CFLAGS += -I$(ELKSSL_INC)
LDFLAGS +=

SRCS = myapp.c
OBJS = $(SRCS:.c=$(OBJ_EXT))

myapp: $(OBJS) $(ELKSSL_LIB)
	$(LD) $(LDFLAGS) -o myapp $(OBJS) $(ELKSSL_LIB) $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o myapp

.PHONY: clean
```

**Build your application:**
```bash
cd elkscmd/myapp
make
```

### Method 2: Direct Compilation

For standalone ELKS applications:

```bash
# Compile your source
wcc -ml -os -0 -bt=none -I$TOPDIR/Macssl-elks/build-elks/include \
    -I$TOPDIR/libc/include -I$TOPDIR/elks/include \
    myapp.c -fo=myapp.obj

# Link with elkssl
wlink system dos \
    name myapp.exe \
    file myapp.obj \
    library $TOPDIR/Macssl-elks/build-elks/lib/elkssl.lib \
    library $TOPDIR/libc/libc.a
```

### Method 3: ELKS CMake Projects

**CMakeLists.txt:**
```cmake
cmake_minimum_required(VERSION 3.10)
project(myapp C)

set(ELKSSL_DIR ${CMAKE_SOURCE_DIR}/../../Macssl-elks)

include_directories(
    ${ELKSSL_DIR}/build-elks/include
    ${CMAKE_SOURCE_DIR}/../../libc/include
    ${CMAKE_SOURCE_DIR}/../../elks/include
)

add_executable(myapp myapp.c)
target_link_libraries(myapp ${ELKSSL_DIR}/build-elks/lib/elkssl.lib)
```

---

## Configuration

### Customizing Memory Limits

Edit `Macssl-elks/Project/config.h`:

```c
/* Reduce SSL buffer size to save RAM */
#define MBEDTLS_SSL_MAX_CONTENT_LEN 1024  /* Default: 2048 */
#define MBEDTLS_SSL_OUT_CONTENT_LEN 1024  /* Default: 2048 */
#define MBEDTLS_SSL_IN_CONTENT_LEN  1024  /* Default: 2048 */

/* Reduce max RSA key size */
#define MBEDTLS_MPI_MAX_SIZE 128          /* Default: 256 */
```

**After changing config.h, rebuild:**
```bash
./build-elks-elkssl.sh clean
./build-elks-elkssl.sh
```

### Changing Memory Model

The library automatically uses the memory model defined in `$TOPDIR/libc/watcom.model`.

**To change:**
```bash
# Edit the model file
echo "MODEL=s" > $TOPDIR/libc/watcom.model  # Small model
echo "MODEL=m" > $TOPDIR/libc/watcom.model  # Medium model
echo "MODEL=c" > $TOPDIR/libc/watcom.model  # Compact model
echo "MODEL=l" > $TOPDIR/libc/watcom.model  # Large model (default)

# Rebuild elkssl and libc
cd $TOPDIR/libc && make clean && make
cd $TOPDIR/Macssl-elks && ./build-elks-elkssl.sh clean && ./build-elks-elkssl.sh
```

**Memory Model Guidelines:**
- **Small (-ms)**: 64KB code + 64KB data total — **Not recommended for TLS**
- **Medium (-mm)**: >64KB code, 64KB data — May work for simple TLS clients
- **Compact (-mc)**: 64KB code, >64KB data — Possible but limited
- **Large (-ml)**: >64KB code, >64KB data — **Recommended for TLS**

---

## Example Application

### Minimal TLS Client

**tls_client.c:**
```c
#include <stdio.h>
#include <string.h>
#include "ssl.h"
#include "entropy.h"
#include "ctr_drbg.h"
#include "error.h"

/* Simple send/receive wrappers (adapt to your socket API) */
static int sockfd;

int net_send(void *ctx, const unsigned char *buf, size_t len) {
    /* Implement socket write */
    return -1;
}

int net_recv(void *ctx, unsigned char *buf, size_t len) {
    /* Implement socket read */
    return -1;
}

int main(void) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    int ret;

    /* Initialize */
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    /* Seed RNG */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, NULL, 0);
    if (ret != 0) {
        printf("RNG seed failed: -0x%x\n", -ret);
        return 1;
    }

    /* Setup SSL config */
    mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    /* Setup SSL context */
    mbedtls_ssl_setup(&ssl, &conf);
    mbedtls_ssl_set_hostname(&ssl, "example.com");
    mbedtls_ssl_set_bio(&ssl, &sockfd, net_send, net_recv, NULL);

    /* Perform handshake */
    printf("Connecting...\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("Handshake failed: -0x%x\n", -ret);
            goto exit;
        }
    }
    printf("Connected!\n");

    /* Send request */
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    mbedtls_ssl_write(&ssl, (unsigned char *)req, strlen(req));

    /* Read response */
    unsigned char buf[512];
    while ((ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1)) > 0) {
        buf[ret] = '\0';
        printf("%s", buf);
    }

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 0;
}
```

**Makefile:**
```makefile
ELKSSL = ../../Macssl-elks
CC = wcc
LD = wlink

CFLAGS = -ml -os -0 -bt=none -I$(ELKSSL)/build-elks/include
LDFLAGS = system dos

tls_client: tls_client.obj
	$(LD) $(LDFLAGS) name tls_client.exe file tls_client.obj \
	      library $(ELKSSL)/build-elks/lib/elkssl.lib

tls_client.obj: tls_client.c
	$(CC) $(CFLAGS) tls_client.c -fo=tls_client.obj

clean:
	rm -f *.obj tls_client.exe
```

---

## Implementing Custom Entropy Source

The default `entropy_elks.c` returns dummy data. For production, replace it:

**Project/entropy_elks.c:**
```c
#include "entropy_poll.h"

int mbedtls_hardware_poll(void *data,
                          unsigned char *output, size_t len, size_t *olen)
{
    /* Example: Read from hardware RNG or system source */
    FILE *fp = fopen("/dev/random", "rb");
    if (!fp) return -1;
    
    *olen = fread(output, 1, len, fp);
    fclose(fp);
    
    return (*olen == len) ? 0 : -1;
}
```

**Rebuild after changes:**
```bash
./build-elks-elkssl.sh clean
./build-elks-elkssl.sh
```

---

## Troubleshooting

### Build Errors

**Error: `wcc: command not found`**
- OpenWatcom not installed or not in PATH
- Solution: `source $TOPDIR/env.sh` or install OpenWatcom

**Error: `Unable to open 'xxx.h'`**
- Missing header file dependency
- Check that all required headers are present in `Project/`

**Error: Linker fails with "undefined symbol"**
- Missing source file in build script
- Check `SOURCES=()` array in `build-elks-elkssl.sh`

### Runtime Errors

**Stack overflow during handshake**
- Increase stack size: `ulimit -s 16384` or configure in ELKS
- Reduce `MBEDTLS_SSL_MAX_CONTENT_LEN` in `config.h`

**Memory allocation failure**
- Increase heap size in ELKS configuration
- Reduce buffer sizes in `config.h`

**Handshake fails with `-0x7200`**
- Certificate verification failed
- Use `MBEDTLS_SSL_VERIFY_NONE` for testing
- Load proper CA certificates for production

### Debug Build

Enable verbose output:

```c
#include "debug.h"

void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    printf("%s:%d: %s", file, line, str);
}

mbedtls_debug_set_threshold(3);  /* 0-4, higher = more verbose */
mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
```

---

## Performance Considerations

### Memory Usage

Approximate memory requirements per TLS connection:

- **SSL context**: ~4 KB
- **Handshake buffers**: ~6 KB
- **Certificate chain**: Variable (1-4 KB typical)
- **RSA operations**: ~1-2 KB stack
- **Total minimum**: ~12-16 KB per connection

### Optimization Tips

1. **Reduce buffer sizes** in `config.h`:
   ```c
   #define MBEDTLS_SSL_MAX_CONTENT_LEN 1024
   ```

2. **Limit certificate chain depth**:
   ```c
   #define MBEDTLS_X509_MAX_INTERMEDIATE_CA 4
   ```

3. **Use session resumption** (if supported by server):
   ```c
   mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED);
   ```

4. **Disable unused features** in `config.h`:
   - Comment out unused cipher suites
   - Disable SHA-512 if only SHA-256 is needed
   - Disable MD5 if not required

---

## Adding elkssl to ELKS Distribution

### System-wide Installation

To make elkssl available to all ELKS applications:

1. **Build elkssl**:
   ```bash
   cd $TOPDIR/Macssl-elks
   ./build-elks-elkssl.sh
   ```

2. **Install library**:
   ```bash
   mkdir -p $TOPDIR/lib
   cp build-elks/lib/elkssl.lib $TOPDIR/lib/
   ```

3. **Install headers**:
   ```bash
   mkdir -p $TOPDIR/include/elkssl
   cp build-elks/include/*.h $TOPDIR/include/elkssl/
   ```

4. **Update applications**:
   ```c
   #include <elkssl/ssl.h>
   #include <elkssl/entropy.h>
   ```

### Include in ELKS Build System

Add to top-level `Makefile`:

```makefile
all: kernel libc elkssl apps

elkssl:
	cd Macssl-elks && ./build-elks-elkssl.sh

clean: clean-elkssl
clean-elkssl:
	cd Macssl-elks && ./build-elks-elkssl.sh clean
```

---

## Version Information

Get library version at runtime:

```c
#include "version.h"

printf("elkssl version: %s\n", MBEDTLS_VERSION_STRING);
printf("Based on Mbed TLS %d.%d.%d\n",
       MBEDTLS_VERSION_MAJOR,
       MBEDTLS_VERSION_MINOR,
       MBEDTLS_VERSION_PATCH);
```

---

## License Notes

All copyright notices have been removed from the source code. The library is provided as-is for use with ELKS.

Original source: Mbed TLS 2.29 (Apache-2.0 OR GPL-2.0-or-later)

---

## Additional Resources

- **ELKS Documentation**: `$TOPDIR/Documentation/`
- **OpenWatcom Manual**: https://open-watcom.github.io/
- **Mbed TLS API**: https://mbed-tls.readthedocs.io/
- **TLS 1.2 RFC 5246**: https://www.rfc-editor.org/rfc/rfc5246

---

## Support and Contributing

For issues specific to the ELKS port:
- Check ELKS kernel logs for memory/stack issues
- Verify OpenWatcom version compatibility
- Test with minimal configuration first

For general TLS questions:
- Refer to Mbed TLS documentation
- Check cipher suite compatibility
- Validate certificate formats (PEM/DER)
