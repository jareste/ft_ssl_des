#include <ft_algorithm_g.h>
#include <md5.h>
#include <sha256.h>
#include <whirlpool.h>
#include <blake2s.h>
#include <base64.h>
// #include <des.h>

const algorithm_entry g_algorithms[] =
{
    { "md5", MD5, md5_main },
    { "sha256", SHA256, sha256_main },
    { "whirlpool", WHIRLPOOL, whirlpool_main },
    { "blake2s", BLAKE2S, blake2s_main },
    { "base64", BASE64, base64_main },
    { "des", DES, NULL },
    { "des-ecb", DES_ECB, NULL },
    { "des-cbc", DES_CBC, NULL },
    { "des-ofb", DES_OFB, NULL },
    { "des3", DES3, NULL },
    { "des3-ecb", DES3_ECB, NULL },
    { "des3-cbc", DES3_CBC, NULL },
    { "des3-ofb", DES3_OFB, NULL },
    { "help", HELP, NULL },
    { "--help", HELP, NULL },
    { "-h", HELP, NULL },
    { NULL, NONE, NULL }
};