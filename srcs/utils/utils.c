#include <md5.h>
#include <ft_list.h>
#include <ft_malloc.h>
#include <sha256.h>
#include <string.h>
#include <ft_ssl.h>
#include <utils.h>
#include <whirlpool.h>
#include <blake2s.h>
#include <base64.h>

#include <stdio.h>

void exec_algorithm(void *encrypt, int flags, algorithms algorithm)
{
    list_t *list = (list_t *)encrypt;

    /* SHOULD NEVER HAPPEN */
    ft_assert(list, "Fatal error: No input data.");

    while (list)
    {
        switch (algorithm)
        {
        case MD5:
            md5_main(get_data(list), get_procedence(list), get_type(list), flags);
            break;
        case SHA256:
            sha256_main(get_data(list), get_procedence(list), get_type(list), flags);
            break;
        case WHIRLPOOL:
            whirlpool_main(get_data(list), get_procedence(list), get_type(list), flags);
            break;
        case BLAKE2S:
            blake2s_main(get_data(list), get_procedence(list), get_type(list), flags);
            break;
        case BASE64:
            base64_main(get_data(list), get_procedence(list), get_type(list), flags);
            break;
        default:
            ft_assert(0, "Fatal error: Unknown algorithm.");
            break;
        }
        list = list_get_next(list);
    }

    /* reset list pointer for cleaning */
    list = (list_t *)encrypt;
    list_clear(&list);
}

void print_without_newline(const char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
    {
        fwrite(str, 1, len - 1, stdout);
    }
    else
    {
        printf("%s", str);
    }
}

void usage(int code)
{
    printf("%s\n", USAGE);
    exit(code);
}

void print_usage(algorithms algo, int code)
{
    switch (algo)
    {
    case MD5:
        printf("%s\n", USAGE_MD5);
        break;
    case SHA256:
        printf("%s\n", USAGE_SHA256);
        break;
    case WHIRLPOOL:
        printf("%s\n", USAGE_WHIRLPOOL);
        break;
    default:
        /* NEVER HERE */
        usage(code);
       break;
    }
    exit(code);
}