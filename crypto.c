#include <openssl/evp.h>
#include <openssl/hmac.h>

int main()
{
    EVP_CIPHER_CTX ctx;
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char in[16] = {0};
    unsigned char out[32]; /* at least one block longer than in[] */
    int outlen1, outlen2;

    EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
    EVP_EncryptUpdate(&ctx, out, &outlen1, in, sizeof(in));
    EVP_EncryptFinal(&ctx, out + outlen1, &outlen2);

    printf("ciphertext length: %d\n", outlen1 + outlen2);

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
