#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <errno.h>
#include <gcrypt.h>
#include "crypto_if.h"

static const char *gnu_init(void)
{
	(void)gcry_check_version(GCRYPT_VERSION);
	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	return "gcrypt";
}

static unsigned long gnu_encrypt(void *key, int keylen, void *iv,
			void *pt, void *ct, int tlen)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd;

	if ((err = gcry_cipher_open(&hd, GCRY_CIPHER_AES128,
					GCRY_CIPHER_MODE_CBC, 0)))
		return (unsigned long)err;
	if ((err = gcry_cipher_setkey(hd, key, keylen)))
		return (unsigned long)err;
	if ((err = gcry_cipher_setiv(hd, iv, keylen)))
		return (unsigned long)err;
	if ((err = gcry_cipher_encrypt(hd, ct, tlen, pt, tlen)))
		return (unsigned long)err;
	if ((err = gcry_cipher_reset(hd)))
		return (unsigned long)err;
	return 0UL;
}

static unsigned long gnu_decrypt(void *key, int keylen, void *iv,
			void *ct, void *pt, int tlen)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd;

	if ((err = gcry_cipher_open(&hd, GCRY_CIPHER_AES128,
					GCRY_CIPHER_MODE_CBC, 0)))
		return (unsigned long)err;
	if ((err = gcry_cipher_setkey(hd, key, keylen)))
		return (unsigned long)err;
	if ((err = gcry_cipher_setiv(hd, iv, keylen)))
		return (unsigned long)err;
	if ((err = gcry_cipher_decrypt(hd, pt, tlen, ct, tlen)))
		return (unsigned long)err;
	if ((err = gcry_cipher_reset(hd)))
		return (unsigned long)err;
	return 0UL;
}

static unsigned long gnu_hash(void *pt, int tlen, void *tag, int *taglen)
{
	gcry_error_t err;
	gcry_md_hd_t hd;

	unsigned int dlen = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
	if (*taglen < dlen)
		return (unsigned long)gcry_error_from_errno(ENOMEM);
	if ((err = gcry_md_open(&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_SECURE)))
		return (unsigned long)err;
	gcry_md_write(hd, pt, tlen);
	gcry_md_final(hd);
	memcpy(tag, gcry_md_read(hd, GCRY_MD_SHA1), dlen);
	gcry_md_close(hd);
	*taglen = dlen;
	return 0UL;
}

static unsigned long gnu_hmac(void *key, int keylen, void *pt, int tlen,
			void *tag, int *taglen)
{
	gcry_error_t err;
	gcry_md_hd_t hd;

	unsigned int dlen = gcry_md_get_algo_dlen(GCRY_MD_SHA1);
	if (*taglen < dlen)
		return (unsigned long)gcry_error_from_errno(ENOMEM);
	if ((err = gcry_md_open(&hd, GCRY_MD_SHA1, GCRY_MD_FLAG_SECURE |
							GCRY_MD_FLAG_HMAC)))
		return (unsigned long)err;
	if ((err = gcry_md_setkey(hd, key, keylen)))
		return (unsigned long)err;
	gcry_md_write(hd, pt, tlen);
	gcry_md_final(hd);
	memcpy(tag, gcry_md_read(hd, GCRY_MD_SHA1), dlen);
	gcry_md_close(hd);
	*taglen = dlen;
	return 0UL;
}

static const char *gnu_errstr(unsigned long err)
{
	return gcry_strerror((gcry_error_t)err);
}

struct crypto_interface gnu_crypto_if = {
	.init		= gnu_init,
	.encrypt	= gnu_encrypt,
	.decrypt	= gnu_decrypt,
	.hash		= gnu_hash,
	.hmac		= gnu_hmac,
	.errstr		= gnu_errstr,
};
