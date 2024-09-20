#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>
#include <ft_ssl.h>

/* output can be checked with: https://www.md5hashgenerator.com */

void md5_main(char *encrypt, char* procedence, input_type type, int flags, size_t size);

#endif
