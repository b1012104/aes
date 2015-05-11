#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define THREAD_NUM 2
#define BUFSIZE 1024
#define ENC 1
#define DEC 0

static pthread_mutex_t *mutex_buf;

struct ARGS{
	char rfname[256];
	char wfname[256];
	int mode;
};

static void lock_callback(int mode, int type, char *file, int line)
{
	if (mode & CRYPTO_LOCK) {
		pthread_mutex_lock(&(mutex_buf[type]));
	}
	else {
		pthread_mutex_unlock(&(mutex_buf[type]));
	}
}

static unsigned long thread_id(void)
{
	return (unsigned long)pthread_self();
}

static void init_locks(void)
{
	int i;

	mutex_buf=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_init(&(mutex_buf[i]), NULL);
	}

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
		inlen = fread(inbuf, 1, 1024, in);
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
	struct ARGS *args = (struct ARGS *) arg;
	FILE *rfp, *wfp;
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
	return 0;
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

int main(int argc, char *argv[])
{
	pthread_t tid[THREAD_NUM];
	int i, j;
	int mode_flag = ENC;
	int argi;
	int error;
	const char *in = argv[1];
	const char *ou = argv[2];
	DIR *dp;
	struct dirent *dir;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [src] [dist] [ENC|DEC]\n", argv[0]);
		exit(1);
	}

	long fnum = get_file_num(in);
	struct ARGS args[fnum];

	if (argc == 4) {
		if (strcmp(argv[3], "ENC") == 0) {
			mode_flag = ENC;
		} else if (strcmp(argv[3], "DEC") == 0){
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
	printf("crypto_num_locks = %d\n", CRYPTO_num_locks());
	printf("fnum = %ld\n", fnum);
	printf("THREAD_NUM = %d\n", THREAD_NUM);
	printf("fnum / THREAD_NUM = %ld\n", (long)(fnum / THREAD_NUM));
#endif

	/* start threads */
	argi = 0;
	for (i = 0; i < (long)(fnum / THREAD_NUM); i++) {
		for(j = 0; j < THREAD_NUM; j++) {
			error = pthread_create(&tid[j],
					NULL,
					do_crypt_thread,
					(void *)&args[argi++]);
			if(error)
				fprintf(stderr, "Couldn't run thread number %d, errno %d\n", j, error);
		}

		for(j = 0; j < THREAD_NUM; j++) {
			error = pthread_join(tid[j], NULL);
			fprintf(stderr, "Thread %d terminated\n", j);
		}
	}

	/* run remaining threads */
	for(j = 0; j < fnum % THREAD_NUM; j++) {
		error = pthread_create(&tid[j],
				NULL,
				do_crypt_thread,
				(void *)&args[argi++]);
		if(error)
			fprintf(stderr, "Couldn't run thread number %d, errno %d\n", j, error);
	}

	for(j = 0; j < fnum % THREAD_NUM; j++) {
		error = pthread_join(tid[j], NULL);
		fprintf(stderr, "Thread %d terminated\n", j);
	}
	/* threads end here */

	clear_locks();

	return 0;
}
