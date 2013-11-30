#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include "serial.h"
#include "crypto.h"
#include "authobj.h"
#include "pcsc_cr.h"

struct _hash_obj {
	const char *err;
	unsigned char hash[HASHSIZE];
};

static struct _hash_obj
make_challenge(const char *uid, const char *pass, const char *nonce)
{
	struct _hash_obj ho = {0};
	unsigned long rc;
	serializer_t srl;
	int datasize = strlen(uid) + strlen(pass) + strlen(nonce) +
			4 * sizeof(short);
	unsigned char *data = alloca(datasize);
	int hashsize = sizeof(ho.hash);

	serial_init(&srl, data, datasize);
	if (serial_put(&srl, uid, strlen(uid)) != strlen(uid)) {
		ho.err = "challenge: serialization of uid failed";
	} else if (serial_put(&srl, pass, strlen(pass)) != strlen(pass)) {
		ho.err = "challenge: serialization of pass failed";
	} else if (serial_put(&srl, nonce, strlen(nonce)) != strlen(nonce)) {
		ho.err = "challenge: serialization of nonce failed";
	} else if (serial_put(&srl, NULL, 0) != 0) {
		ho.err = "challenge: serialization of terminator failed";
	}
	if (!ho.err) {
		if ((rc = hash(data, serial_size(&srl), &ho.hash, &hashsize))) {
			ho.err = crypto_errstr(rc);
		} else if (hashsize != sizeof(ho.hash)) {
			ho.err = "challenge: hash size is wrong";
		}
	}
	memset(data, 0, datasize);
	return ho;
}

static struct _hash_obj
make_key(const unsigned char *challenge, const int challengesize,
	const unsigned char *secret, const int secsize)
{
	struct _hash_obj ho = {0};
	unsigned long rc;
	int keysize = sizeof(ho.hash);

	if ((rc = hmac(secret, secsize, challenge, challengesize,
			&ho.hash, &keysize))) {
		ho.err = crypto_errstr(rc);
	} else if (keysize != sizeof(ho.hash)) {
		ho.err = "make_key: hash size is wrong";
	}
	return ho;
}

static struct _hash_obj
fetch_key(const unsigned char *challenge, const int challengesize)
{
	struct _hash_obj ho = {0};
	int rc;
	int keysize = sizeof(ho.hash);

	if ((rc = pcsc_cr(challenge, challengesize, ho.hash, &keysize))) {
		ho.err = pcsc_errstr(rc);
	}
	return ho;
}

static struct _auth_obj
make_authobj(const unsigned char *key, const int keysize,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize)
{
	struct _auth_obj ao = {0};
	unsigned long rc;
	unsigned char *data;
	int datasize;
	unsigned char datahash[HASHSIZE];
	int datahashsize = HASHSIZE;
	serializer_t srl;

	datasize = ((secsize + paysize + HASHSIZE + 4 * sizeof(short) - 1) /
			CBLKSIZE + 1) * CBLKSIZE;
	data = alloca(datasize);
	serial_init(&srl, data, datasize);
	if (serial_put(&srl, secret, secsize) != secsize) {
		ao.err = "authobj: serialization of secret failed";
	} else if (serial_put(&srl, payload, paysize) != paysize) {
		ao.err = "authobj: serialization of payload failed";
	} else if ((rc = hash(data, serial_size(&srl),
				datahash, &datahashsize))) {
		ao.err = crypto_errstr(rc);
	} else if (serial_put(&srl, datahash, datahashsize) != datahashsize) {
		ao.err = "authobj: serialization of hash failed";
	} else if (serial_put(&srl, NULL, 0) != 0) {
		ao.err = "authobj: serialization of terminator failed";
	}

	if (!ao.err) {
		unsigned long lrc;
		int osize = ((serial_size(&srl) -1) / CBLKSIZE + 1) * CBLKSIZE;

		if ((ao.buffer = malloc(osize)) == NULL) {
			ao.err = "authobj: malloc failed";
		} else if ((lrc = encrypt(key, CBLKSIZE, data,
					ao.buffer, osize))) {
			ao.err = crypto_errstr(lrc);
		} else {
			ao.authobj = ao.buffer;
			ao.authsize = osize;
		}
	}

	memset(data, 0, datasize);
	return ao;
}

static int parse_authobj(const unsigned char *key, const int keysize,
		const unsigned char *buffer, const int bufsize,
		unsigned char *secret, int *secsize,
		unsigned char *payload, int *paysize)
{
	int datasize = bufsize;
	unsigned char *data = alloca(datasize);
	serializer_t srl;
	int tsize;
	unsigned char myhash[HASHSIZE];
	int myhashsize = HASHSIZE;
	unsigned char theirhash[HASHSIZE];
	int theirhashsize = HASHSIZE;

	if (decrypt(key, CBLKSIZE, buffer, data, datasize))
		return 1;
	serial_init(&srl, data, datasize);
	tsize = *secsize;
	*secsize = serial_get(&srl, secret, tsize);
	if (*secsize > tsize || *secsize <= 0) return 1;
	tsize = *paysize;
	*paysize = serial_get(&srl, payload, tsize);
	if (*paysize > tsize || *paysize <= 0) return 1;
	if (hash(data, serial_size(&srl), myhash, &myhashsize))
		return 1;
	theirhashsize = serial_get(&srl, theirhash, theirhashsize);
	if (theirhashsize != HASHSIZE) return 1;
	if ((myhashsize != theirhashsize) ||
	    memcmp(myhash, theirhash, myhashsize))
		return 1;
	return 0;
}

struct _auth_obj new_authobj(const char *userid, const char *password,
				const char *nonce,
			const unsigned char *secret, const int secsize,
			const unsigned char *payload, const int paysize)
{
	struct _auth_obj ao = {0};
	struct _hash_obj ho_chal, ho_key;

	ho_chal = make_challenge(userid, password, nonce);
	if (ho_chal.err) {
		ao.err = ho_chal.err;
		return ao;
	}
	ho_key = make_key(ho_chal.hash, sizeof(ho_chal.hash), secret, secsize);
	if (ho_key.err) {
		ao.err = ho_key.err;
		return ao;
	}
	ao = make_authobj(ho_key.hash, sizeof(ho_key.hash),
			secret, secsize, payload, paysize);
	memset(&ho_chal, 0, sizeof(ho_chal));
	memset(&ho_key, 0, sizeof(ho_key));
	return ao;
}

struct _auth_obj verify_authobj(const char *userid, const char *password,
				const char *oldnonce, const char *newnonce,
			const unsigned char *authobj, const int authsize)
{
	struct _auth_obj ao = {0};
	struct _hash_obj ho_chal, ho_key;

	ho_chal = make_challenge(userid, password, oldnonce);
	if (ho_chal.err) {
		ao.err = ho_chal.err;
		return ao;
	}
	ho_key = fetch_key(ho_chal.hash, sizeof(ho_chal.hash));
	if (ho_key.err) {
		ao.err = ho_key.err;
		return ao;
	}
	memset(&ho_chal, 0, sizeof(ho_chal));
	memset(&ho_key, 0, sizeof(ho_key));
	return ao;
}

struct _auth_obj reload_authobj(const char *userid, const char *password,
				const char *oldnonce, const char *newnonce,
			const unsigned char *authobj, const int authsize,
			const unsigned char *payload, const int paysize)
{
	struct _auth_obj ao = {0};
	struct _hash_obj ho_chal, ho_key;

	ho_chal = make_challenge(userid, password, oldnonce);
	if (ho_chal.err) {
		ao.err = ho_chal.err;
		return ao;
	}
	ho_key = fetch_key(ho_chal.hash, sizeof(ho_chal.hash));
	if (ho_key.err) {
		ao.err = ho_key.err;
		return ao;
	}
	memset(&ho_chal, 0, sizeof(ho_chal));
	memset(&ho_key, 0, sizeof(ho_key));
	return ao;
}
