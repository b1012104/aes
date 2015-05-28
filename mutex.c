#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define BUFSIZE 1024
#define ENC 1
#define DEC 0
#define MAX_FILENAME_LEN 256

static pthread_mutex_t *mutex_buf;
int thread_num = 1; /* default 1 thread */
long fnum;

struct ARGS{
    char rfname[MAX_FILENAME_LEN];
    char wfname[MAX_FILENAME_LEN];
    int mode;
    int thread_count;
};

static void lock_callback(int mode, int type, char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        pthread_mutex_lock(&(mutex_buf[type]));
    else
        pthread_mutex_unlock(&(mutex_buf[type]));
}

static unsigned long thread_id(void)
{
    return (unsigned long)pthread_self();
}

static void init_locks(void)
{
    int i;

    mutex_buf=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_init(&(mutex_buf[i]), NULL);

    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback((void (*)())lock_callback);
}

static void clear_locks(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        pthread_mutex_destroy(&(mutex_buf[i]));

    OPENSSL_free(mutex_buf);
}

static int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
    unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX ctx;

    unsigned char key[] = "0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";

    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
            do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

    for(;;) {
        inlen = fread(inbuf, 1, BUFSIZE, in);
        if(inlen <= 0) break;
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 1;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_cleanup(&ctx);
    return 0;
}

static void *do_crypt_thread(void *arg)
{
    struct ARGS *args = (struct ARGS *)arg;
    FILE *rfp, *wfp;
    int i;

    for (i = args->thread_count; i < fnum; i += thread_num) {
        rfp = fopen(args->rfname, "r");
        if (!rfp) {
            perror("fopen");
            pthread_exit(NULL);
        }
        wfp = fopen(args->wfname, "w");
        if (!wfp) {
            perror("fopen");
            pthread_exit(NULL);
        }

        if(do_crypt(rfp, wfp, args->mode)) {
            printf("failed encryption\n");
            pthread_exit(NULL);
        }

        fclose(rfp);
        fclose(wfp);
        args += thread_num;
    }
    pthread_exit(NULL);
}

static long get_file_num(const char *dname)
{
    long count =  0;
    DIR *dp;
    struct dirent *dir;

    dp = opendir(dname);
    if (!dp) {
        perror("opendir:");
        return -1;
    }
    while ((dir = readdir(dp)) != NULL) {
        /* except parent and current directory */
        if (strcmp(dir->d_name, ".") != 0 &&  strcmp(dir->d_name, "..") != 0)
            count++;
    }
    closedir(dp);

    return count;
}

static void show_usage(char *program)
{
    fprintf(stderr, "Usage: %s [options] [src] [dist] [ENC|DEC]\n", program);
}

static struct option longopts[] = {
    {"thread", required_argument, NULL, 't'},
    {"help",   no_argument,        NULL, 'h'},
    {0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
    int i;
    int mode_flag = ENC; /* default ENC flag */
    int error;
    int opt;
    int argi;
    const char *in;
    const char *ou;
    DIR *dp;
    struct dirent *dir;

    if (argc < 2) {
        show_usage(argv[0]);
        exit(1);
    }

    while ((opt = getopt_long(argc, argv, "t:h", longopts, NULL)) != -1) {
        switch (opt) {
            case 't':
                thread_num = atoi(optarg);
                if (thread_num <= 0) {
                    fprintf(stderr, "invalid option argument\n");
                    exit(1);
                }
                break;
            case 'h':
                show_usage(argv[0]);
                exit(0);
                break;
            case '?':
                show_usage(argv[0]);
                exit(1);
                break;
        }
    }

    in = argv[optind];
    ou = argv[optind + 1];

    pthread_t threads[thread_num];
    fnum = get_file_num(in);
    struct ARGS args[fnum];

    if (argv[optind + 2]) {
        if (strcmp(argv[optind + 2], "ENC") == 0) {
            mode_flag = ENC;
        } else if (strcmp(argv[optind + 2], "DEC") == 0){
            mode_flag = DEC;
        }
    }

    dp = opendir(in);
    i = 0;
    while ((dir = readdir(dp)) != NULL) {
        if (strcmp(dir->d_name, ".") != 0 &&
                strcmp(dir->d_name, "..") != 0) {
            strcpy(args[i].rfname, in);
            strcat(args[i].rfname, "/");
            strcat(args[i].rfname, dir->d_name);
            strcpy(args[i].wfname, ou);
            strcat(args[i].wfname, "/");
            strcat(args[i].wfname, dir->d_name);
            args[i].mode = mode_flag;
            i++;
        }
    }

    init_locks();

#ifdef DEBUG
    printf("thread num      : %d\n", thread_num);
    printf("file num        : %ld\n", fnum);
    printf("crypto_num_locks: %d\n", CRYPTO_num_locks());
#endif

    /* start threads */
    if (thread_num > fnum)
        thread_num = fnum;
    for (i = 0; i < thread_num; i++) {
        args[i].thread_count = i;
        error = pthread_create(&threads[i],
                NULL,
                do_crypt_thread,
                (void *)&args[i]);
        if(error)
            fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, error);
    }

    for(i = 0; i < thread_num; i++) {
        error = pthread_join(threads[i], NULL);
#ifdef DEBUG
        fprintf(stderr, "Thread %d terminated\n", i);
#endif
    }
    /* threads end here */

    clear_locks();

    return 0;
}
