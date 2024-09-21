#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H

#include <ft_ssl.h>
#include <stddef.h>
#include <stdint.h>

#define WHIRLPOOL_DIGEST_LENGTH 64

void whirlpool_main(char *data, void* procedence, input_type type, int flags, size_t size);

#endif
