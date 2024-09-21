#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <ft_ssl.h>

void sha256_main(char *encrypt, void* procedence, input_type type, int flags, size_t size);

#endif
