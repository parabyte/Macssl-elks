/**
 * \file platform.h
 *
 * \brief Trimmed platform glue for building Mbed TLS on ELKS.
 *
 *        The upstream header supports many host environments with optional
 *        runtime hooks and configurable stdlib bindings.
 *        The ELKS port keeps things simple: rely on the libc shipped with
 *        the ELKS toolchain and expose only the entry points that matter.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_PLATFORM_H
#define MBEDTLS_PLATFORM_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(MBEDTLS_HAVE_TIME)
#include <time.h>
#endif

/** Hardware accelerator failed */
#define MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED     -0x0070
/** The requested feature is not supported by the platform */
#define MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ELKS uses the toolchain's libc directly. Hard-wire the default stdlib
 * bindings so the rest of the library does not need to care about other
 * environments.
 */
#define MBEDTLS_PLATFORM_STD_SNPRINTF   snprintf
#define MBEDTLS_PLATFORM_STD_VSNPRINTF  vsnprintf
#define MBEDTLS_PLATFORM_STD_PRINTF     printf
#define MBEDTLS_PLATFORM_STD_FPRINTF    fprintf
#define MBEDTLS_PLATFORM_STD_CALLOC     calloc
#define MBEDTLS_PLATFORM_STD_FREE       free
#define MBEDTLS_PLATFORM_STD_EXIT       exit
#if defined(MBEDTLS_HAVE_TIME)
#define MBEDTLS_PLATFORM_STD_TIME       time
#endif
#define MBEDTLS_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS
#define MBEDTLS_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE

/*
 * Memory management helpers.
 *
 * When MBEDTLS_PLATFORM_CALLOC/MBEDTLS_PLATFORM_FREE macros are provided
 * (our ELKS config does this), the dynamic setter is not emitted. The
 * declarations remain for completeness and to match platform.c.
 */
#if defined(MBEDTLS_PLATFORM_MEMORY) &&                 \
    !(defined(MBEDTLS_PLATFORM_CALLOC_MACRO) &&         \
      defined(MBEDTLS_PLATFORM_FREE_MACRO))
void *mbedtls_calloc(size_t n, size_t size);
void mbedtls_free(void *ptr);
int mbedtls_platform_set_calloc_free(void *(*calloc_func)(size_t, size_t),
                                     void (*free_func)(void *));
#else
#undef mbedtls_calloc
#undef mbedtls_free
#define mbedtls_calloc MBEDTLS_PLATFORM_CALLOC_MACRO
#define mbedtls_free   MBEDTLS_PLATFORM_FREE_MACRO
#endif

/*
 * Formatted output helpers.
 */
#undef mbedtls_snprintf
#if defined(MBEDTLS_PLATFORM_SNPRINTF_MACRO)
#define mbedtls_snprintf   MBEDTLS_PLATFORM_SNPRINTF_MACRO
#else
#define mbedtls_snprintf   MBEDTLS_PLATFORM_STD_SNPRINTF
#endif

#undef mbedtls_vsnprintf
#if defined(MBEDTLS_PLATFORM_VSNPRINTF_MACRO)
#define mbedtls_vsnprintf   MBEDTLS_PLATFORM_VSNPRINTF_MACRO
#else
#define mbedtls_vsnprintf   MBEDTLS_PLATFORM_STD_VSNPRINTF
#endif

#undef mbedtls_printf
#if defined(MBEDTLS_PLATFORM_PRINTF_MACRO)
#define mbedtls_printf   MBEDTLS_PLATFORM_PRINTF_MACRO
#else
#define mbedtls_printf   MBEDTLS_PLATFORM_STD_PRINTF
#endif

#undef mbedtls_fprintf
#if defined(MBEDTLS_PLATFORM_FPRINTF_MACRO)
#define mbedtls_fprintf   MBEDTLS_PLATFORM_FPRINTF_MACRO
#else
#define mbedtls_fprintf   MBEDTLS_PLATFORM_STD_FPRINTF
#endif

/*
 * Exit helpers.
 */
#undef mbedtls_exit
#if defined(MBEDTLS_PLATFORM_EXIT_MACRO)
#define mbedtls_exit   MBEDTLS_PLATFORM_EXIT_MACRO
#else
#define mbedtls_exit   MBEDTLS_PLATFORM_STD_EXIT
#endif

#define MBEDTLS_EXIT_SUCCESS MBEDTLS_PLATFORM_STD_EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE MBEDTLS_PLATFORM_STD_EXIT_FAILURE

#if defined(MBEDTLS_PLATFORM_EXIT_ALT)
int mbedtls_platform_set_exit(void (*exit_func)(int status));
#endif

/*
 * NV seed helpers are compiled out by default on ELKS but the declarations
 * are kept under their original guards to avoid accidental ABI drift if the
 * entropy NV seed source is ever enabled.
 */
#if defined(MBEDTLS_ENTROPY_NV_SEED)
int mbedtls_platform_std_nv_seed_read(unsigned char *buf, size_t buf_len);
int mbedtls_platform_std_nv_seed_write(unsigned char *buf, size_t buf_len);
#if defined(MBEDTLS_PLATFORM_NV_SEED_ALT)
extern int (*mbedtls_nv_seed_read)(unsigned char *buf, size_t buf_len);
extern int (*mbedtls_nv_seed_write)(unsigned char *buf, size_t buf_len);
int mbedtls_platform_set_nv_seed(
    int (*nv_seed_read_func)(unsigned char *buf, size_t buf_len),
    int (*nv_seed_write_func)(unsigned char *buf, size_t buf_len));
#else
#define mbedtls_nv_seed_read    mbedtls_platform_std_nv_seed_read
#define mbedtls_nv_seed_write   mbedtls_platform_std_nv_seed_write
#endif /* MBEDTLS_PLATFORM_NV_SEED_ALT */
#endif /* MBEDTLS_ENTROPY_NV_SEED */

/*
 * Platform setup / teardown.
 */
#if !defined(MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)
typedef struct mbedtls_platform_context {
    char dummy;
} mbedtls_platform_context;
#else
#include "platform_alt.h"
#endif /* MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT */

int mbedtls_platform_setup(mbedtls_platform_context *ctx);
void mbedtls_platform_teardown(mbedtls_platform_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_PLATFORM_H */
