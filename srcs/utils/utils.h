#ifndef UTILS_H
#define UTILS_H

#include <ft_ssl.h>

void exec_algorithm(void *encrypt, int flags, algorithms algorithm);
void print_without_newline(const char *str);
void usage(int code);
void print_usage(algorithms algo, int code);

#define USAGE_MD5 "Usage: ft_ssl md5 [flags] [file/string]\n\n" \
                  "Flags:\n" \
                  "  -p             Echo STDIN to STDOUT and append the checksum to STDOUT.\n" \
                  "  -q             Quiet mode - only the hash is printed.\n" \
                  "  -r             Reverse the format of the output (hash followed by file/string).\n" \
                  "  -s  <string>   Print the sum of the given string.\n\n" \
                  "Examples:\n" \
                  "  ft_ssl md5 -p -q -s \"hola\" file.txt\n" \
                  "  ft_ssl md5 -r -s \"hello world\" file.txt\n" \
                  "  ft_ssl md5 file1.txt file2.txt\n"

#define USAGE_SHA256 "Usage: ft_ssl sha256 [flags] [file/string]\n\n" \
                     "Flags:\n" \
                     "  -p             Echo STDIN to STDOUT and append the checksum to STDOUT.\n" \
                     "  -q             Quiet mode - only the hash is printed.\n" \
                     "  -r             Reverse the format of the output (hash followed by file/string).\n" \
                     "  -s  <string>   Print the sum of the given string.\n\n" \
                     "Examples:\n" \
                     "  ft_ssl sha256 -p -q -s \"hola\" file.txt\n" \
                     "  ft_ssl sha256 -r -s \"hello world\" file.txt\n" \
                     "  ft_ssl sha256 file1.txt file2.txt\n"

#define USAGE_WHIRLPOOL "Usage: ft_ssl whirlpool [flags] [file/string]\n\n" \
                        "Flags:\n" \
                        "  -p             Echo STDIN to STDOUT and append the checksum to STDOUT.\n" \
                        "  -q             Quiet mode - only the hash is printed.\n" \
                        "  -r             Reverse the format of the output (hash followed by file/string).\n" \
                        "  -s  <string>   Print the sum of the given string.\n\n" \
                        "Examples:\n" \
                        "  ft_ssl whirlpool -p -q -s \"hola\" file.txt\n" \
                        "  ft_ssl whirlpool -r -s \"hello world\" file.txt\n" \
                        "  ft_ssl whirlpool file1.txt file2.txt\n"

#define USAGE "Usage: ft_ssl command [flags] [file/string]\n\n" \
              "Commands:\n" \
              "  md5       Compute the MD5 hash.\n" \
              "  sha256    Compute the SHA-256 hash.\n" \
              "  whirlpool Compute the Whirlpool hash.\n" \
              "\n"\
              "Flags:\n" \
              "  -p             Echo STDIN to STDOUT and append the checksum to STDOUT.\n" \
              "  -q             Quiet mode - only the hash is printed.\n" \
              "  -r             Reverse the format of the output (hash followed by file/string).\n" \
              "  -s  <string>   Print the sum of the given string.\n\n" \
              "Examples:\n" \
              "  ft_ssl md5 -p -q -s \"hola\" file\n" \
              "  ft_ssl sha256 -r -s \"hello world\" file.txt\n"

#endif