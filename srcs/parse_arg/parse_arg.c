/***************************/
/*        INCLUDES         */
/***************************/

#include <ft_malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <ft_ssl.h>
#include <ft_list.h>
#include <errno.h>
#include <utils.h>
#include <ft_algorithm_g.h>

/***************************/
/*        DEFINES          */
/***************************/
// typedef void (*algorithm_func)(char *encrypt, char *procedence, input_type type, int flags);

// typedef struct {
//     const char*     name;
//     algorithms      alg;
//     algorithm_func  func;
// } algorithm_entry;

// static const algorithm_entry g_algorithms[] = {
//     { "md5", MD5, md5_main },
//     { "sha256", SHA256, sha256_main },
//     { "whirlpool", WHIRLPOOL },
//     { "blake2s", BLAKE2S },
//     { "base64", BASE64 },
//     { "des", DES },
//     { "des-ecb", DES_ECB },
//     { "des-cbc", DES_CBC },
//     { "des-ofb", DES_OFB },
//     { "des3", DES3 },
//     { "des3-ecb", DES3_ECB },
//     { "des3-cbc", DES3_CBC },
//     { "des3-ofb", DES3_OFB },
//     { "help", HELP },
//     { "--help", HELP },
//     { "-h", HELP },
//     { NULL, NONE }
// };

/***************************/
/*        METHODS          */
/***************************/

static void read_file(const char *filename, char **content, size_t *size)
{
    if (access(filename, F_OK) != 0)
    {
        fprintf(stderr, "ft_ssl: %s: No such file or directory\n", filename);
        return;
    }

    if (access(filename, R_OK) != 0)
    {
        fprintf(stderr, "ft_ssl: %s: Permission denied\n", filename);
        return;
    }

    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "ft_ssl: %s: %s\n", filename, strerror(errno));
        /* NEVER HERE */
        ft_assert(file, "Fatal error: Could not open file.");
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    *content = malloc(file_size + 1);

    size_t read_size = fread(*content, 1, file_size, file);
    if (read_size != (size_t)file_size)
    {
        perror("Error reading file");
        free(*content);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    (*content)[file_size] = '\0';

    if (size)
        *size = file_size;

    fclose(file);
}


static void read_stdin(char **encrypt, size_t* size)
{
    size_t buffer_size = 1024;
    size_t total_size = 0;
    char *buffer = malloc(buffer_size);
    int c;

    while ((c = getchar()) != EOF)
    {
        if (total_size + 1 >= buffer_size)
        {
            buffer_size *= 2;
            char *new_buffer = realloc(buffer, buffer_size);
            buffer = new_buffer;
        }
        buffer[total_size++] = (char)c;
    }

    buffer[total_size] = '\0';

    *encrypt = buffer;
    if (size)
        *size = total_size;
}

static algorithms check_algorithm(const char *algorithm)
{
    if (algorithm == NULL) goto error;

    for (int i = 0; get_algo_name(i) != NULL; i++)
    {
        if (strcasecmp(algorithm, g_algorithms[i].name) == 0)
        {
            return get_algo_alg(i);
        }
    }

error:
    fprintf(stderr, "ft_ssl: Error: '%s' is an invalid command.\n", algorithm);
    print_usage(NONE, EXIT_FAILURE); /* EXITS */
    return NONE;
}

static bool can_read_file(algorithms algo)
{
    switch (algo)
    {
        case MD5:
        case SHA256:
        case WHIRLPOOL:
        case BLAKE2S:
            return true;
        default:
            return false;
    }
}

void check_flag(algorithms algo, int flag, char flag_name)
{
    switch (algo)
    {
        case MD5:
        case SHA256:
        case WHIRLPOOL:
        case BLAKE2S:
            if (flag & DIGEST_FLAGS)
                return;
            break;
        case BASE64:
            if (flag & CIPHER_FLAGS)
                    return;
                break;
        case DES:
        case DES_ECB:
        case DES_CBC:
        case DES_OFB:
        case DES3:
        case DES3_ECB:
        case DES3_CBC:
        case DES3_OFB:
            if (flag & CIPHER_FLAGS)
                return;
            break;
        default:
            print_usage(NONE, EXIT_FAILURE);
            break;
    }
    fprintf(stderr, "ft_ssl: Error: Invalid flag combination %c with algo %s.\n", flag_name, get_algo_name(algo));
    print_usage(NONE, EXIT_FAILURE);
}

bool is_valid_hex_key(const char* key)
{
    if (strlen(key) != 16)
    {
        fprintf(stderr, "Invalid key length. Key must be 16 hexadecimal characters.\n");
        exit(1);
        return false;
    }

    for (int i = 0; i < 16; i++)
    {
        if (!isxdigit(key[i]))
        {
            fprintf(stderr, "Invalid character detected. Key must contain only hexadecimal characters (0-9, a-f, A-F).\n");
            exit(1);
            return false;
        }
    }

    return true;
}

bool is_valid_hex_iv(const char* iv)
{
    if (strlen(iv) != 16)
    {
        fprintf(stderr, "Invalid IV length. IV must be 16 hexadecimal characters.\n");
        exit(1);
        return false;
    }

    for (int i = 0; i < 16; i++)
    {
        if (!isxdigit(iv[i]))
        {
            fprintf(stderr, "Invalid character detected. IV must contain only hexadecimal characters (0-9, a-f, A-F).\n");
            exit(1);
            return false;
        }
    }

    return true;
}


bool is_valid_hex_salt(const char* salt)
{
    if (strlen(salt) != 8)
    {
        fprintf(stderr, "Invalid salt length. Salt must be 8 hexadecimal characters.\n");
        exit(1);
        return false;
    }

    for (int i = 0; i < 8; i++)
    {
        if (!isxdigit(salt[i]))
        {
            fprintf(stderr, "Invalid character detected. Salt must contain only hexadecimal characters (0-9, a-f, A-F).\n");
            exit(1);
            return false;
        }
    }

    return true;
}

void do_flag_s(algorithms algo, list_t** list, char* optarg)
{
    if (optarg == NULL)
    {
        fprintf(stderr, "ft_ssl: Error: -s flag requires an argument.\n");
        exit(1);
    }

    switch (algo)
    {
        case MD5:
        case SHA256:
        case WHIRLPOOL:
        case BLAKE2S:
            if (optarg)
            {
                list_add_last(list, optarg, optarg, TYPE_NORMAL, strlen(optarg));
            }
            else
            {
                fprintf(stderr, "Option -s contains garbage as argument: %s.\n", optarg);
                fprintf(stderr, "This will become fatal error in the future.\n");
            }
            break;
        case BASE64:
            if (optarg)
            {
                list_add_last(list, optarg, optarg, TYPE_NORMAL, strlen(optarg));
            }
            else
            {
                fprintf(stderr, "Option -s contains garbage as argument: %s.\n", optarg);
                fprintf(stderr, "This will become fatal error in the future.\n");
            }
            break;
        case DES:
        case DES_ECB:
        case DES_CBC:
        case DES_OFB:
        case DES3:
        case DES3_ECB:
        case DES3_CBC:
        case DES3_OFB:
            if (optarg && is_valid_hex_salt(optarg))
            {
                list_add_last(list, optarg, optarg, TYPE_SALT, strlen(optarg));
            }
            else
            {
                fprintf(stderr, "Fatal error checking salt.\n");
                exit(1);
            }
            break;
        default:
            ft_assert(0, "Invalid algorithm.");
            break;
    }
}

void parse_args(int argc, char *argv[], int *flags, void** encrypt, algorithms* algorithm)
{
    int opt;
    char* stdin_buffer = NULL;
    list_t **list = (list_t **)encrypt;
    size_t size = 0;

    *algorithm = check_algorithm(argv[1]);

    while ((opt = getopt(argc, argv, "?hpqrs:edi:o:ak:v:")) != -1)
    {
        switch (opt)
        {
            case '?':
            case 'h':
                print_usage(*algorithm, EXIT_SUCCESS);
                exit(0);
            case 'p':
                check_flag(*algorithm, P_FLAG, 'p');
                *flags |= P_FLAG;
                break;
            case 'q':
                check_flag(*algorithm, Q_FLAG, 'q');
                *flags |= Q_FLAG;
                break;
            case 'r':
                check_flag(*algorithm, R_FLAG, 'r');
                *flags |= R_FLAG;
                break;
            case 's':
            /* TODO cannot save it into list, rarete.... */
                check_flag(*algorithm, S_FLAG, 's');
                do_flag_s(*algorithm, list, optarg);
                break;
            case 'e':
                check_flag(*algorithm, E_FLAG, 'e');
                if (*flags & D_FLAG)
                {
                    fprintf(stderr, "ft_ssl: Error: Cannot use -d and -e together.\n");
                    print_usage(*algorithm, EXIT_FAILURE);
                    exit(1);
                }
                *flags |= E_FLAG;
                break;
            case 'd':
                check_flag(*algorithm, D_FLAG, 'd');
                if (*flags & E_FLAG)
                {
                    fprintf(stderr, "ft_ssl: Error: Cannot use -d and -e together.\n");
                    print_usage(*algorithm, EXIT_FAILURE);
                    exit(1);
                }
                *flags |= D_FLAG;
                break;
            case 'i':
                check_flag(*algorithm, I_FLAG, 'i');
                if (optarg)
                {
                    read_file(optarg, &stdin_buffer, &size);
                    list_add_last(list, stdin_buffer, optarg, TYPE_FILE, size);
                    free(stdin_buffer);
                    stdin_buffer = NULL;
                }
                else
                {
                    fprintf(stderr, "Option -i contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            case 'o':
            /* TODO notok*/
                check_flag(*algorithm, O_FLAG, 'o');
                if (optarg)
                {
                    list_add_last(list, optarg, optarg, TYPE_NORMAL, strlen(optarg));
                }
                else
                {
                    fprintf(stderr, "Option -o contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            case 'a':
                check_flag(*algorithm, A_FLAG, 'a');
                *flags |= A_FLAG;
                break;
            case 'k': /* TODO cannot save it into list, rarete.... */
                check_flag(*algorithm, K_FLAG, 'k');
                if (optarg && is_valid_hex_key(optarg))
                {
                    list_add_last(list, optarg, optarg, TYPE_KEY, strlen(optarg));
                }
                else
                {
                    fprintf(stderr, "Option -k contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            case 'v': /* TODO cannot save it into list, rarete.... */
                check_flag(*algorithm, V_FLAG, 'v');
                if (optarg && is_valid_hex_iv(optarg))
                {
                    list_add_last(list, optarg, optarg, TYPE_NORMAL, strlen(optarg));
                }
                else
                {
                    fprintf(stderr, "Option -v contains garbage as argument: %s.\n", optarg);
                    fprintf(stderr, "This will become fatal error in the future.\n");
                }
                break;
            default:
                print_usage(*algorithm, EXIT_FAILURE);
                exit(1);
        }
    }

    stdin_buffer = NULL;
    for (int i = optind+1; i < argc; i++)
    {
        if (!can_read_file(*algorithm))
        {
            fprintf(stderr, "ft_ssl: Error: %s does not accept files as input.\n", get_algo_name(*algorithm));
            print_usage(*algorithm, EXIT_FAILURE);
            exit(1);
        }

        read_file(argv[i], &stdin_buffer, &size);
        if (stdin_buffer)
        {
            list_add_last(list, stdin_buffer, argv[i], TYPE_FILE, size);
            free(stdin_buffer);
            stdin_buffer = NULL;
        }
    }

    if (optind >= argc)
    {
        fprintf(stderr, "Expected argument after options\n");
        print_usage(*algorithm, EXIT_FAILURE);
        exit(1);
    }

    /* chekc if something to read from stdin. */
    if (!isatty(fileno(stdin)) && (*flags & P_FLAG || *list == NULL)) {
        read_stdin(&stdin_buffer, &size);
        
        list_add_last(list, stdin_buffer,\
        (*flags & P_FLAG) ? stdin_buffer : "stdin", (*flags & P_FLAG) ? TYPE_STDIN_NORMAL : TYPE_STDIN,\
        size);

        free(stdin_buffer);
    }

    /* no input recieved, so we read from stdin. */
    if ((*list == NULL))
    {
        read_stdin(&stdin_buffer, &size);
        
        list_add_last(list, stdin_buffer,\
        (*flags & P_FLAG) ? stdin_buffer : "stdin", (*flags & P_FLAG) ? TYPE_STDIN_NORMAL : TYPE_STDIN\
        , size);

        free(stdin_buffer);
    }
}