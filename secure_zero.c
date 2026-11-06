#include "secure_zero.h"

void secure_zero(void* ptr, size_t size)
{
    if (ptr == NULL) return;

    volatile unsigned char* p = (volatile unsigned char*)ptr;

    while (size > 0)
    {
        *p++ = 0;
        --size;
    }
}