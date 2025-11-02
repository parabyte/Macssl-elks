#include "common.h"

#if defined(MBEDTLS_ENTROPY_HARDWARE_ALT)

#include <stddef.h>
#include <stdint.h>

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	size_t i;
	static uint32_t state = 0x6b6c7355UL;
	/* LCG stub; replace with a true hardware source for production. */

	state ^= (uint32_t)(unsigned long)(void *)data;

	for (i = 0; i < len; ++i) {
		state = state * 1103515245UL + 12345UL;
		output[i] = (unsigned char)(state >> 16);
	}

	if (olen != NULL) {
		*olen = len;
	}

	return 0;
}

#endif
