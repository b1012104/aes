#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/evp.h>

#define BUFSIZE 1024
#define ENC 1
#define DEC 0

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

int main(int argc, char *argv[])
{
	FILE *ifp, *ofp;

	if (argc != 4) {
		fprintf(stderr, "Need filename\n");
		exit(1);
	}

	if (!strcmp(argv[3], "enc") == 0 && !strcmp(argv[3], "dec") == 0) {
		fprintf(stderr, "Error\n");
		exit(1);
	}

	if (strcmp(argv[1], argv[2]) == 0) {
		fprintf(stderr, "Error\n");
		exit(1);
	}

	ifp = fopen(argv[1], "r");
	if (!ifp) {
		perror("fopen");
		exit(1);
	}

	ofp = fopen(argv[2], "w");
	if (!ofp) {
		perror("fopen");
		exit(1);
	}

	if (strcmp(argv[3], "enc") == 0) {
		do_crypt(ifp, ofp, ENC);
	} else {
		do_crypt(ifp, ofp, DEC);
	}

	fclose(ifp);
	fclose(ofp);

	exit(0);
}
