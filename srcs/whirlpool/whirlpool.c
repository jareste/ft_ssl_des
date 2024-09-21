#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ft_ssl.h>
#include <utils.h>
#include "whirlpool_sbox.h"

#define whirlpool_block_size 64

#define IS_ALIGNED_64(p) (0 == (7 & (uintptr_t)(p)))

#if defined(_MSC_VER)
#define RHASH_INLINE __inline
#elif defined(__GNUC__) && !defined(__STRICT_ANSI__)
#define RHASH_INLINE inline
#elif defined(__GNUC__)
#define RHASH_INLINE __inline__
#else
#define RHASH_INLINE
#endif


void rhash_swap_copy_str_to_u64(void* to, int index, const void* from, size_t length);

/* bswap definitions */
#if (defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC__ > 4 || __GNUC_MINOR__ >= 3))
/* GCC >= 4.3 */
# define bswap_32(x) __builtin_bswap32(x)
# define bswap_64(x) __builtin_bswap64(x)

#elif defined(__clang__) && defined(__has_builtin)
# if __has_builtin(__builtin_bswap32) && __has_builtin(__builtin_bswap64)
/* Clang with bswap builtins */
#  define bswap_32(x) __builtin_bswap32(x)
#  define bswap_64(x) __builtin_bswap64(x)
# endif

#elif (_MSC_VER > 1300) && (defined(CPU_IA32) || defined(CPU_X64)) /* MS VC */
# define bswap_32(x) _byteswap_ulong((unsigned long)x)
# define bswap_64(x) _byteswap_uint64((__int64)x)

#else
/* fallback to generic bswap definition */
static inline uint32_t bswap_32(uint32_t x)
{
# if defined(__GNUC__) && defined(CPU_IA32) && !defined(__i386__) && !defined(RHASH_NO_ASM)
	__asm("bswap\t%0" : "=r" (x) : "0" (x)); /* gcc x86 version */
	return x;
# else
	x = ((x << 8) & 0xFF00FF00u) | ((x >> 8) & 0x00FF00FFu);
	return (x >> 16) | (x << 16);
# endif
}

static inline uint64_t bswap_64(uint64_t x)
{
	union {
		uint64_t ll;
		uint32_t l[2];
	} w, r;
	w.ll = x;
	r.l[0] = bswap_32(w.l[1]);
	r.l[1] = bswap_32(w.l[0]);
	return r.ll;
}
#endif /* bswap definitions */



// #if IS_BIG_ENDIAN
// # define be2me_32(x) (x)
// # define be2me_64(x) (x)
// # define le2me_32(x) bswap_32(x)
// # define le2me_64(x) bswap_64(x)

// # define be32_copy(to, index, from, length) memcpy((char*)(to) + (index), (from), (length))
// # define le32_copy(to, index, from, length) rhash_swap_copy_str_to_u32((to), (index), (from), (length))
// # define be64_copy(to, index, from, length) memcpy((char*)(to) + (index), (from), (length))
// # define le64_copy(to, index, from, length) rhash_swap_copy_str_to_u64((to), (index), (from), (length))
// # define me64_to_be_str(to, from, length) memcpy((to), (from), (length))
// # define me64_to_le_str(to, from, length) rhash_swap_copy_u64_to_str((to), (from), (length))

// #else /* IS_BIG_ENDIAN */
# define be2me_32(x) bswap_32(x)
# define be2me_64(x) bswap_64(x)
# define le2me_32(x) (x)
# define le2me_64(x) (x)

# define be32_copy(to, index, from, length) rhash_swap_copy_str_to_u32((to), (index), (from), (length))
# define le32_copy(to, index, from, length) memcpy((char*)(to) + (index), (from), (length))
# define be64_copy(to, index, from, length) rhash_swap_copy_str_to_u64((to), (index), (from), (length))
# define le64_copy(to, index, from, length) memcpy((char*)(to) + (index), (from), (length))
# define me64_to_be_str(to, from, length) rhash_swap_copy_u64_to_str((to), (from), (length))
# define me64_to_le_str(to, from, length) memcpy((to), (from), (length))
// #endif /* IS_BIG_ENDIAN */

void rhash_swap_copy_str_to_u64(void* to, int index, const void* from, size_t length)
{
	/* if all pointers and length are 64-bits aligned */
	if ( 0 == (( (uintptr_t)to | (uintptr_t)from | (uintptr_t)index | length ) & 7) )
	{
		/* copy aligned memory block as 64-bit integers */
		const uint64_t* src = (const uint64_t*)from;
		const uint64_t* end = (const uint64_t*)((const char*)src + length);
		uint64_t* dst = (uint64_t*)((char*)to + index);
		while (src < end) 
		{
			*(dst++) = bswap_64( *(src++) );
		}
	}
	else
	{
		const char* src = (const char*)from;
		for (length += index; (size_t)index < length; index++)
		{
			((char*)to)[index ^ 7] = *(src++);
		}
	}
}

/* algorithm context */
typedef struct whirlpool_ctx
{
	uint64_t hash[8];    /* 512-bit algorithm internal hashing state */
	unsigned char message[whirlpool_block_size]; /* 512-bit buffer to hash */

	/* Note: original algorith uses 256-bit counter, allowing to hash up to
	   2^256 bits sized message. For optimization we use here 64-bit counter,
	   thus reducing maximal message size to 2^64 bits = 2 Exbibytes = 2^21 TiB) */
	uint64_t length;     /* number of processed bytes */
} whirlpool_ctx;

void rhash_whirlpool_init(struct whirlpool_ctx* ctx)
{
	ctx->length = 0;
	memset(ctx->hash, 0, sizeof(ctx->hash));
}

/* Algorithm S-Box */
extern uint64_t rhash_whirlpool_sbox[8][256];

#define WHIRLPOOL_OP(src, shift) ( \
	rhash_whirlpool_sbox[0][(int)(src[ shift      & 7] >> 56)       ] ^ \
	rhash_whirlpool_sbox[1][(int)(src[(shift + 7) & 7] >> 48) & 0xff] ^ \
	rhash_whirlpool_sbox[2][(int)(src[(shift + 6) & 7] >> 40) & 0xff] ^ \
	rhash_whirlpool_sbox[3][(int)(src[(shift + 5) & 7] >> 32) & 0xff] ^ \
	rhash_whirlpool_sbox[4][(int)(src[(shift + 4) & 7] >> 24) & 0xff] ^ \
	rhash_whirlpool_sbox[5][(int)(src[(shift + 3) & 7] >> 16) & 0xff] ^ \
	rhash_whirlpool_sbox[6][(int)(src[(shift + 2) & 7] >>  8) & 0xff] ^ \
	rhash_whirlpool_sbox[7][(int)(src[(shift + 1) & 7]      ) & 0xff])

/**
 * The core transformation. Process a 512-bit block.
 *
 * @param hash algorithm state
 * @param block the message block to process
 */
static void rhash_whirlpool_process_block(uint64_t* hash, uint64_t* p_block)
{
	int i;                /* loop counter */
	uint64_t K[2][8];       /* key */
	uint64_t state[2][8];   /* state */

	/* alternating binary flags */
	unsigned int m = 0;

	/* the number of rounds of the internal dedicated block cipher */
	const int number_of_rounds = 10;

	/* array used in the rounds */
	static const uint64_t rc[10] = {
		I64(0x1823c6e887b8014f),
		I64(0x36a6d2f5796f9152),
		I64(0x60bc9b8ea30c7b35),
		I64(0x1de0d7c22e4bfe57),
		I64(0x157737e59ff04ada),
		I64(0x58c9290ab1a06b85),
		I64(0xbd5d10f4cb3e0567),
		I64(0xe427418ba77d95d8),
		I64(0xfbee7c66dd17479e),
		I64(0xca2dbf07ad5a8333)
	};

	/* map the message buffer to a block */
	for (i = 0; i < 8; i++)
	{
		/* store K^0 and xor it with the intermediate hash state */
		K[0][i] = hash[i];
		state[0][i] = be2me_64(p_block[i]) ^ hash[i];
		hash[i] = state[0][i];
	}

	/* iterate over algorithm rounds */
	for (i = 0; i < number_of_rounds; i++)
	{
		/* compute K^i from K^{i-1} */
		K[m ^ 1][0] = WHIRLPOOL_OP(K[m], 0) ^ rc[i];
		K[m ^ 1][1] = WHIRLPOOL_OP(K[m], 1);
		K[m ^ 1][2] = WHIRLPOOL_OP(K[m], 2);
		K[m ^ 1][3] = WHIRLPOOL_OP(K[m], 3);
		K[m ^ 1][4] = WHIRLPOOL_OP(K[m], 4);
		K[m ^ 1][5] = WHIRLPOOL_OP(K[m], 5);
		K[m ^ 1][6] = WHIRLPOOL_OP(K[m], 6);
		K[m ^ 1][7] = WHIRLPOOL_OP(K[m], 7);

		/* apply the i-th round transformation */
		state[m ^ 1][0] = WHIRLPOOL_OP(state[m], 0) ^ K[m ^ 1][0];
		state[m ^ 1][1] = WHIRLPOOL_OP(state[m], 1) ^ K[m ^ 1][1];
		state[m ^ 1][2] = WHIRLPOOL_OP(state[m], 2) ^ K[m ^ 1][2];
		state[m ^ 1][3] = WHIRLPOOL_OP(state[m], 3) ^ K[m ^ 1][3];
		state[m ^ 1][4] = WHIRLPOOL_OP(state[m], 4) ^ K[m ^ 1][4];
		state[m ^ 1][5] = WHIRLPOOL_OP(state[m], 5) ^ K[m ^ 1][5];
		state[m ^ 1][6] = WHIRLPOOL_OP(state[m], 6) ^ K[m ^ 1][6];
		state[m ^ 1][7] = WHIRLPOOL_OP(state[m], 7) ^ K[m ^ 1][7];

		m = m ^ 1;
	}

	/* apply the Miyaguchi-Preneel compression function */
	hash[0] ^= state[0][0];
	hash[1] ^= state[0][1];
	hash[2] ^= state[0][2];
	hash[3] ^= state[0][3];
	hash[4] ^= state[0][4];
	hash[5] ^= state[0][5];
	hash[6] ^= state[0][6];
	hash[7] ^= state[0][7];
}

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param size length of the message chunk
 */
void rhash_whirlpool_update(whirlpool_ctx* ctx, const unsigned char* msg, size_t size)
{
	unsigned index = (unsigned)ctx->length & 63;
	unsigned left;
	ctx->length += size;

	/* fill partial block */
	if (index)
	{
		left = whirlpool_block_size - index;
		memcpy(ctx->message + index, msg, (size < left ? size : left));
		if (size < left) return;

		/* process partial block */
		rhash_whirlpool_process_block(ctx->hash, (uint64_t*)ctx->message);
		msg  += left;
		size -= left;
	}
	while (size >= whirlpool_block_size)
	{
		uint64_t* aligned_message_block;
		if (IS_ALIGNED_64(msg))
		{
			/* the most common case is processing of an already aligned message
			without copying it */
			aligned_message_block = (uint64_t*)msg;
		}
		else
		{
			memcpy(ctx->message, msg, whirlpool_block_size);
			aligned_message_block = (uint64_t*)ctx->message;
		}

		rhash_whirlpool_process_block(ctx->hash, aligned_message_block);
		msg += whirlpool_block_size;
		size -= whirlpool_block_size;
	}
	if (size)
	{
		/* save leftovers */
		memcpy(ctx->message, msg, size);
	}
}

/**
 * Store calculated hash into the given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param result calculated hash in binary form
 */
void rhash_whirlpool_final(whirlpool_ctx* ctx, unsigned char* result)
{
	unsigned index = (unsigned)ctx->length & 63;
	uint64_t* msg64 = (uint64_t*)ctx->message;

	/* pad message and run for last block */
	ctx->message[index++] = 0x80;

	/* if no room left in the message to store 256-bit message length */
	if (index > 32)
	{
		/* then pad the rest with zeros and process it */
		while (index < 64)
		{
			ctx->message[index++] = 0;
		}
		rhash_whirlpool_process_block(ctx->hash, msg64);
		index = 0;
	}
	/* due to optimization actually only 64-bit of message length are stored */
	while (index < 56)
	{
		ctx->message[index++] = 0;
	}
	msg64[7] = be2me_64(ctx->length << 3);
	rhash_whirlpool_process_block(ctx->hash, msg64);

	/* save result hash */
	be64_copy(result, 0, ctx->hash, 64);
}

void whirlpool_main(const char *data, void* procedence_void, input_type type, int flags, size_t size)
{    
    whirlpool_ctx ctx;
    char* procedence = (char*)procedence_void;
    rhash_whirlpool_init(&ctx);
    
    rhash_whirlpool_update(&ctx, (const unsigned char *)data, size);
    
    unsigned char result[64];
    rhash_whirlpool_final(&ctx, result);
    
    /**/
    if (!(flags & Q_FLAG) && !(flags & R_FLAG))
    {
        switch (type)
        {
            case TYPE_NORMAL:
                printf("WHIRLPOOL (\"");
                print_without_newline(data);
                printf("\") = ");
                break;
            case TYPE_FILE:
                printf("WHIRLPOOL (");
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

    /* Print digest */
    for (size_t i = 0; i < sizeof(result); i++)
	{
        printf("%02x", result[i]);
    }

    /**/
    if (!(flags & Q_FLAG) && (flags & R_FLAG))
    {
        switch (type)
        {
            case TYPE_NORMAL:
                printf(" \"");
                print_without_newline(data);
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