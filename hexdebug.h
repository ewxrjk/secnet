#ifndef HEXDEBUG_H
#define HEXDEBUG_H

#include <stdio.h>
#include <sys/types.h>

static inline void hexdebug(FILE *file, const void *buffer, size_t len)
{
    const uint8_t *array=buffer;
    size_t i;
    for (i=0; i<len; i++)
	fprintf(file,"%02x",array[i]);
}

#endif /*HEXDEBUG_H*/
