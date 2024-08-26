#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ft_malloc.h>
#include <utils.h>
#include <ft_ssl.h>

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char base64_index[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
    ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
    ['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38, ['n'] = 39,
    ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47,
    ['w'] = 48, ['x'] = 49, ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
    ['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63
};

static char* base64_decode(const char* input)
{
    int len = strlen(input);
    int pad = (input[len - 1] == '=' ? (input[len - 2] == '=' ? 2 : 1) : 0);
    int output_len = (len * 3) / 4 - pad;
    char* output = (char*)malloc(output_len + 1);

    int i, j;
    for (i = 0, j = 0; i < len;)
    {
        u_int32_t sextet_a = input[i] == '=' ? 0 & i++ : base64_index[(unsigned char)input[i++]];
        u_int32_t sextet_b = input[i] == '=' ? 0 & i++ : base64_index[(unsigned char)input[i++]];
        u_int32_t sextet_c = input[i] == '=' ? 0 & i++ : base64_index[(unsigned char)input[i++]];
        u_int32_t sextet_d = input[i] == '=' ? 0 & i++ : base64_index[(unsigned char)input[i++]];

        u_int32_t triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < output_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < output_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < output_len) output[j++] = triple & 0xFF;
    }

    output[output_len] = '\0';

    return output;
}

static char* base64_encode(const char* input)
{
    int len = strlen(input);
    int pad = (3 - len % 3) % 3;
    int output_len = 4 * ((len + 2) / 3);
    char* output = (char*)malloc(output_len + 1);

    int i, j;
    for (i = 0, j = 0; i < len;)
    {
        u_int32_t octet_a = i < len ? (unsigned char)input[i++] : 0;
        u_int32_t octet_b = i < len ? (unsigned char)input[i++] : 0;
        u_int32_t octet_c = i < len ? (unsigned char)input[i++] : 0;

        u_int32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = base64_table[(triple >> 6) & 0x3F];
        output[j++] = base64_table[triple & 0x3F];
    }

    for (i = 0; i < pad; i++)
    {
        output[output_len - 1 - i] = '=';
    }
    
    output[output_len] = '\0';

    return output;
}

void base64_main(char *encrypt, char* procedence, input_type type, int flags)
{
    char* output = NULL;

    UNUSED_PARAM(procedence);
    UNUSED_PARAM(type);

    if (flags & D_FLAG)
    {
        output = base64_decode(encrypt);
    }
    else
    {
        output = base64_encode(encrypt);
    }

    /* Print digest */
    print_without_newline(output);

    printf("\n");
}