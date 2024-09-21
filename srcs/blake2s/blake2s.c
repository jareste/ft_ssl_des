#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ft_ssl.h>
#include <utils.h>

#define BLAKE2S_BLOCK_SIZE 64
#define BLAKE2S_OUT_SIZE 32
#define BLAKE2S_KEY_SIZE 32
#define BLAKE2S_IV_SIZE 8
#define BLAKE2S_ROUNDS 10

static const uint32_t blake2s_iv[BLAKE2S_IV_SIZE] = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U
};

#define G(r, i, a, b, c, d)                      \
    do {                                         \
        a = a + b + m[blake2s_sigma[r][2 * i + 0]]; \
        d = rotr32(d ^ a, 16);                   \
        c = c + d;                               \
        b = rotr32(b ^ c, 12);                   \
        a = a + b + m[blake2s_sigma[r][2 * i + 1]]; \
        d = rotr32(d ^ a, 8);                    \
        c = c + d;                               \
        b = rotr32(b ^ c, 7);                    \
    } while(0)

static inline uint32_t rotr32(const uint32_t w, const unsigned c)
{
    return (w >> c) | (w << (32 - c));
}

static const uint8_t blake2s_sigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

typedef struct
{
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[BLAKE2S_BLOCK_SIZE];
    size_t buflen;
    size_t outlen;
} blake2s_ctx;

static void blake2s_init(blake2s_ctx *ctx, size_t outlen)
{
    memset(ctx, 0, sizeof(blake2s_ctx));
    memcpy(ctx->h, blake2s_iv, sizeof(blake2s_iv));
    ctx->h[0] ^= 0x01010000 | (uint32_t)outlen;
    ctx->outlen = outlen;
}

static void blake2s_compress(blake2s_ctx *ctx, const uint8_t block[BLAKE2S_BLOCK_SIZE])
{
    uint32_t m[16];
    uint32_t v[16];
    for (size_t i = 0; i < 16; ++i)
    {
        m[i] = (uint32_t)(block[i * 4 + 0]) |
               (uint32_t)(block[i * 4 + 1] << 8) |
               (uint32_t)(block[i * 4 + 2] << 16) |
               (uint32_t)(block[i * 4 + 3] << 24);
    }
    for (size_t i = 0; i < 8; ++i)
    {
        v[i] = ctx->h[i];
    }
    v[8] = blake2s_iv[0];
    v[9] = blake2s_iv[1];
    v[10] = blake2s_iv[2];
    v[11] = blake2s_iv[3];
    v[12] = ctx->t[0] ^ blake2s_iv[4];
    v[13] = ctx->t[1] ^ blake2s_iv[5];
    v[14] = ctx->f[0] ^ blake2s_iv[6];
    v[15] = ctx->f[1] ^ blake2s_iv[7];

    for (size_t r = 0; r < BLAKE2S_ROUNDS; ++r)
    {
        G(r, 0, v[0], v[4], v[8], v[12]);
        G(r, 1, v[1], v[5], v[9], v[13]);
        G(r, 2, v[2], v[6], v[10], v[14]);
        G(r, 3, v[3], v[7], v[11], v[15]);
        G(r, 4, v[0], v[5], v[10], v[15]);
        G(r, 5, v[1], v[6], v[11], v[12]);
        G(r, 6, v[2], v[7], v[8], v[13]);
        G(r, 7, v[3], v[4], v[9], v[14]);
    }

    for (size_t i = 0; i < 8; ++i)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2s_update(blake2s_ctx *ctx, const void *in, size_t inlen)
{
    const uint8_t *pin = (const uint8_t *)in;
    while (inlen > 0)
    {
        size_t left = ctx->buflen;
        size_t fill = BLAKE2S_BLOCK_SIZE - left;
        if (inlen > fill)
        {
            memcpy(ctx->buf + left, pin, fill);
            ctx->buflen += fill;
            pin += fill;
            inlen -= fill;
            ctx->t[0] += BLAKE2S_BLOCK_SIZE;
            if (ctx->t[0] < BLAKE2S_BLOCK_SIZE) {
                ctx->t[1]++;
            }
            blake2s_compress(ctx, ctx->buf);
            ctx->buflen = 0;
        }
        else
        {
            memcpy(ctx->buf + left, pin, inlen);
            ctx->buflen += inlen;
            pin += inlen;
            inlen -= inlen;
        }
    }
}

static void blake2s_final(blake2s_ctx *ctx, void *out)
{
    uint8_t *pout = (uint8_t *)out;
    if (ctx->f[0] != 0)
    {
        return;
    }
    ctx->t[0] += ctx->buflen;
    if (ctx->t[0] < ctx->buflen)
    {
        ctx->t[1]++;
    }
    ctx->f[0] = (uint32_t)-1;
    memset(ctx->buf + ctx->buflen, 0, BLAKE2S_BLOCK_SIZE - ctx->buflen);
    blake2s_compress(ctx, ctx->buf);
    for (size_t i = 0; i < 8; ++i)
    {
        uint32_t h = ctx->h[i];
        pout[i * 4 + 0] = (uint8_t)(h >> 0);
        pout[i * 4 + 1] = (uint8_t)(h >> 8);
        pout[i * 4 + 2] = (uint8_t)(h >> 16);
        pout[i * 4 + 3] = (uint8_t)(h >> 24);
    }
}

void blake2s_main(char *encrypt, void* procedence_void, input_type type, int flags, size_t size)
{
    blake2s_ctx ctx;
    char* procedence = (char*)procedence_void;
    uint8_t hash[BLAKE2S_OUT_SIZE];

    blake2s_init(&ctx, BLAKE2S_OUT_SIZE);
    blake2s_update(&ctx, encrypt, size);
    blake2s_final(&ctx, hash);


    /**/
    if (!(flags & Q_FLAG) && !(flags & R_FLAG))
    {
        switch (type)
        {
            case TYPE_NORMAL:
                printf("BLAKE2s (\"");
                print_without_newline(encrypt);
                printf("\") = ");
                break;
            case TYPE_FILE:
                printf("BLAKE2s (");
                print_without_newline(procedence);
                printf(") = ");
                break;
            case TYPE_STDIN:
                /* handled outside */
                break;
            case TYPE_STDIN_NORMAL:
                /* handled outside */
                break;
            default:
                break;
        }
    }

    if (!(flags & Q_FLAG) && ((type == TYPE_STDIN) || (type == TYPE_STDIN_NORMAL)))
    {
        if (flags & P_FLAG) printf("(\""); else printf("(");
            
        print_without_newline(procedence);
        
        if (flags & P_FLAG) printf("\")= "); else printf(")= ");
            
    }

    /*  PRINT hash */
    for (size_t i = 0; i < BLAKE2S_OUT_SIZE; i++)
    {
        printf("%02x", hash[i]);
    }

    /**/
    if (!(flags & Q_FLAG) && (flags & R_FLAG))
    {
        switch (type)
        {
            case TYPE_NORMAL:
                printf(" \"");
                print_without_newline(encrypt);
                printf("\"");
                break;
            case TYPE_FILE:
                printf(" ");
                print_without_newline(procedence);
                break;
            case TYPE_STDIN:
                /* handled outside */
                break;
            case TYPE_STDIN_NORMAL:
                /* handled outside */
                break;
            default:
                break;
        }
    }

    printf("\n");
}
