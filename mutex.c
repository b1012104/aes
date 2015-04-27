#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#define THREAD_NUM 4
#define BUFSIZE 1024
#define ENC 1
#define DEC 0

static pthread_mutex_t *lockarray;

struct FNAMES{
	char inf[_POSIX_PATH_MAX];
	char ouf[_POSIX_PATH_MAX];
};

static void lock_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lockarray[type]));
  }
  else {
    pthread_mutex_unlock(&(lockarray[type]));
  }
}

static unsigned long thread_id(void)
{
  return (unsigned long)pthread_self();
}

static void init_locks(void)
{
  int i;

  lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
  for (i = 0; i < CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lockarray[i]), NULL);
  }

  CRYPTO_set_id_callback((unsigned long (*)())thread_id);
  CRYPTO_set_locking_callback((void (*)())lock_callback);
}

static void clear_locks(void)
{
  int i;

  CRYPTO_set_locking_callback(NULL);
  for (i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(lockarray[i]));

  OPENSSL_free(lockarray);
}

int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
	/* Allow enough space in output buffer for additional block */
	unsigned char inbuf[BUFSIZE], outbuf[BUFSIZE + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
	EVP_CIPHER_CTX ctx;
	/* Bogus key and IV: we'd normally set these from
	 * another source.
	 */
	unsigned char key[] = "0123456789abcdeF";
	unsigned char iv[] = "1234567887654321";

	/* Don't set key or IV right away; we want to check lengths */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
			do_encrypt);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

	/* Now we can set key and IV */
	EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

	for(;;) {
		inlen = fread(inbuf, 1, 1024, in);
		if(inlen <= 0) break;
		if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
			/* Error */
			EVP_CIPHER_CTX_cleanup(&ctx);
			return 0;
		}
		fwrite(outbuf, 1, outlen, out);
	}
	if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)) {
		/* Error */
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	}
	fwrite(outbuf, 1, outlen, out);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return 1;
}

static void *do_crypto_thread(void *arg)
{
	/* TODO: implement cryption */
    //printf("filenames: %s %s\n", f->inf, f->ouf);

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
		if (strcmp(dir->d_name, ".") != 0 &&  strcmp(dir->d_name, "..") != 0)
			count++;
	}

	closedir(dp);

	return count;
}

static long get_file_size(const char *fname)
{
	FILE *fp;
	long fsize;
	fp = fopen(fname, "r");
	if (!fp) {
		perror("fopen:");
		return -1;
	}

	if (fseek(fp, 0, SEEK_END) == -1) {
		perror("fseek:");
		return -1;
	}

	if ((fsize = ftell(fp)) == -1) {
		perror("ftell:");
		return -1;
	}

	fclose(fp);
	return fsize;
}

int set_filename(char fname[1000][256], char *dname)
{
	DIR *dp;
	int i;
	struct dirent *dir;

	dp = opendir(dname);
	if (!dp) {
		perror("opendir:");
		return -1;
	}

	while ((dir = readdir(dp)) != NULL) {
		if (strcmp(dir->d_name, ".") != 0 &&  strcmp(dir->d_name, "..") != 0)
			strcpy(fname[i++], dir->d_name);
	}

	closedir(dp);
	return 0;
}

int main(int argc, char *argv[])
{
  pthread_t tid[THREAD_NUM];
  int i, j;
  int error;
  const char *in = argv[1];
  const char *ou = argv[2];
  DIR *dp;
  FILE *rfp, *wfp;
  struct dirent *dir;

  if (argc < 2) {
	  fprintf(stderr, "Usage: %s [src] [dist] [ENC|DEC]\n", argv[0]);
	  exit(1);
  }

  long fnum = get_file_num(in);
  char rfname[fnum][256];
  char wfname[fnum][256];

  dp = opendir(in);
  while ((dir = readdir(dp)))

  init_locks();

  for (i = 0; i < abs(fnum / THREAD_NUM); i++) {
	  for(j = 0; j < THREAD_NUM; j++) {
		  error = pthread_create(&tid[j],
				  NULL,
				  do_crypto_thread,
				  (void *)f);
		  if(error)
			  fprintf(stderr, "Couldn't run thread number %d, errno %d\n", j, error);
	  }

	  for(j = 0; j < abs(fnum / THREAD_NUM); j++) {
		  error = pthread_join(tid[j], NULL);
		  fprintf(stderr, "Thread %d terminated\n", j);
	  }
  }

  for(j = 0; j < fnum % THREAD_NUM; j++) {
	  error = pthread_create(&tid[j],
			  NULL,
			  do_crypto_thread,
			  (void *)f);
	  if(error)
		  fprintf(stderr, "Couldn't run thread number %d, errno %d\n", j, error);
  }

  for(j = 0; j < fnum % THREAD_NUM; j++) {
	  error = pthread_join(tid[j], NULL);
	  fprintf(stderr, "Thread %d terminated\n", j);
  }

  clear_locks();

  return 0;
}
