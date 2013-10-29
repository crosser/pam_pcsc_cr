#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "crypto_if.h"

static int ossl_encrypt(void *pt, int ptlen, void *key, int keylen,
			void *ct, int *ctlen)
{
    EVP_CIPHER_CTX ctx;
    unsigned char iv[16] = {0};
    int outlen1, outlen2;

    EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
    EVP_EncryptUpdate(&ctx, ct, &outlen1, pt, ptlen);
    EVP_EncryptFinal(&ctx, ct + outlen1, &outlen2);
    if (outlen1 + outlen2 > *ctlen) return -1;
    *ctlen = outlen1 + outlen2;

    return 0;
}

static int ossl_decrypt()
{
	return 0;
}

static int ossl_hash()
{
	return 0;
}

static int ossl_hmac()
{
	return 0;
}

// result = HMAC(EVP_sha256(), key, 999, data, 888, NULL, NULL);
//               EVP_MD *

// HMAC_CTX hctx;
// HMAC_CTX_init(&hctx);
// if (HMAC_Init(&hctx, key, keylen, EVP_sha1())) success;
// if (HMAC_Update(&hctx, data, datalen)) success;
// if (HMAC_Final(&hctx, &digest, &digestlen)) success
// HMAC_CTX_cleanup(&hctx);

struct crypto_interface ossl_crypto_if = {
	.name		= "openssl",
	.encrypt	= ossl_encrypt,
	.decrypt	= ossl_decrypt,
	.hash		= ossl_hash,
	.hmac		= ossl_hmac,
};
