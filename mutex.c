#include <stdio.h>
#include <pthread.h>
#include <openssl/crypto.h>

#define THREAD_NUM 4

/* we have this global to let the callback get easy access to it */
static pthread_mutex_t *lockarray;

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

static void *do_crypto(void *file)
{
	/* TODO: implement cryption */
    printf("filename: %s\n", (char *)file);
}

int main(int argc, char *argv[])
{
  pthread_t tid[THREAD_NUM];
  int i;
  int error;

  init_locks();

  for(i = 0; i < argc - 1; i++) {
    error = pthread_create(&tid[i],
                           NULL,
                           do_crypto,
                           (void *)file[i]);
    if(error)
      fprintf(stderr, "Couldn't run thread number %d, errno %d\n", i, error);
  }

  for(i = 0; i < argc - 1; i++) {
    error = pthread_join(tid[i], NULL);
    fprintf(stderr, "Thread %d terminated\n", i);
  }

  clear_locks();

  return 0;
}
