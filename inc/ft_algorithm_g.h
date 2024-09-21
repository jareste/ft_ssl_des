#ifndef ALGORITHMS_H
#define ALGORITHMS_H
#include <ft_ssl.h>

typedef void (*algorithm_func)(char *encrypt, void *procedence, input_type type, int flags, size_t size);

typedef struct
{
    const char*     name;
    algorithms      alg;
    algorithm_func  func;
} algorithm_entry;

extern const algorithm_entry g_algorithms[];

#define get_algo_name(x) g_algorithms[x].name
#define get_algo_alg(x) g_algorithms[x].alg
#define get_algo_func(x) g_algorithms[x].func

#endif // ALGORITHMS_H