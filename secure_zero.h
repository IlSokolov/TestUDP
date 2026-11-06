#ifndef SECURE_ZERO_H
#define SECURE_ZERO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	void secure_zero(void* ptr, size_t size);

#ifdef __cplusplus
}
#endif

#endif