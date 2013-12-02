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

static struct _auth_chunk
make_challenge(const char *uid, const char *pass, const char *nonce)
{
	struct _auth_chunk ho = {0};
	unsigned long rc;
	serializer_t srl;
	int datasize = strlen(uid) + strlen(pass) + strlen(nonce) +
			4 * sizeof(short);
	unsigned char *data = alloca(datasize);
	int hashsize = sizeof(ho.data);

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
		if ((rc = hash(data, serial_size(&srl), &ho.data, &hashsize))) {
			ho.err = crypto_errstr(rc);
		} else if (hashsize != sizeof(ho.data)) {
			ho.err = "challenge: hash size is wrong";
		}
	}
	memset(data, 0, datasize);
	return ho;
}

static struct _auth_chunk
make_key(const unsigned char *challenge, const int challengesize,
	const unsigned char *secret, const int secsize)
{
	struct _auth_chunk ho = {0};
	unsigned long rc;
	int keysize = sizeof(ho.data);

	if ((rc = hmac(secret, secsize, challenge, challengesize,
			&ho.data, &keysize))) {
		ho.err = crypto_errstr(rc);
	} else if (keysize != sizeof(ho.data)) {
		ho.err = "make_key: hash size is wrong";
	}
	return ho;
}

static struct _auth_obj
make_authobj(char *userid, char *password, char *nonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paylsize)
{
	struct _auth_obj ao = {0};
	unsigned long rc;
	unsigned char *data;
	int datasize;
	unsigned char datahash[HASHSIZE];
	int datahashsize = HASHSIZE;
	serializer_t srl;

	if (keysize < CBLKSIZE) {
		ao.err = "make authobj: key too short";
		return ao;
	}
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

		if ((ao.buffer = malloc(osize + paysize)) == NULL) {
			ao.err = "make authobj: malloc failed";
		} else if ((lrc = encrypt(key, CBLKSIZE, data,
					ao.buffer, osize))) {
			ao.err = crypto_errstr(lrc);
		} else {
			ao.data = ao.buffer;
			ao.datasize = osize;
			if (payload && paysize) {
				/* payload passthrough */
				ao.payload = ao.data + osize;
				memcpy(ao.payload, payload, paysize);
				ao.paylsize = paysize;
			}
		}
	}

	memset(data, 0, datasize);
	return ao;
}

static struct _auth_obj
parse_authobj(char *userid, char *password, char *nonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *ablob, const int blobsize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize))
{
	unsigned long rc;
	struct _auth_obj ao = {0};

	if (keysize < CBLKSIZE) {
		ao.err = "parse authobj: key too short";
	} else if ((ao.buffer = malloc(bufsize)) == NULL) {
		ao.err = "parse authobj: malloc failed";
	} else if ((rc = decrypt(key, CBLKSIZE, buffer, ao.buffer, bufsize))) {
		ao.err = crypto_errstr(rc);
	} else {
		serializer_t srl;
		unsigned char myhash[HASHSIZE];
		int myhsize = HASHSIZE;
		unsigned char *theirhash;
		int theirhsize;
		unsigned long rc;

		serial_init(&srl, ao.buffer, bufsize);
		if (serial_get(&srl, (void**)&ao.data, &ao.datasize)) {
			ao.err = "mismatch: impossible secret";
		} else if (serial_get(&srl, (void**)&ao.payload, &ao.paylsize)) {
			ao.err = "mismatch: impossible payload";
		} else if ((rc = hash(ao.buffer, serial_size(&srl),
					myhash, &myhsize))) {
			ao.err = crypto_errstr(rc);
		} else if (serial_get(&srl, (void**)&theirhash, &theirhsize)) {
			ao.err = "mismatch: impossible hash";
		} else if (theirhsize != HASHSIZE) {
			ao.err = "mismatch: hash is of wrong size";
		} else if ((myhsize != theirhsize) ||
		    		memcmp(myhash, theirhash, myhsize)) {
			ao.err = "mismatch: different hash";
		}
	}
	return ao;
}

struct _auth_obj authobj(const char *userid, const char *password,
		const char *oldnonce, const char *newnonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paylsize,
		const unsigned char *ablob, const int blobsize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize))
{
	unsigned char *wsecret;
	int wsecsize;
	unsigned char *wpayload;
	int wpaylsize;
	struct _auth_obj old_ao;
	struct _auth_obj new_ao = {0};

	if (!secret || !secsize || !payload) {
		old_ao = parse_authobj(userid, password, oldnonce,
					secret, secsize,
					ablob, blobsize, fetch_key);
		if (old_ao.err) {
			new_ao.err = old_ao.err;
			if (old_ao.buffer) free(old_ao.buffer);
			return new_ao;
		} else {
			if (secret && secsize) {
				wsecret = secret;
				wsecsize = secsize;
			} else {
				wsecret = old_ao.data;
				wsecsize = old_ao.datasize;
			}
			if (payload) {
				wpayload = payload;
				wpaylsize = paylsize;
			} else {
				wpayload = old_ao.payload;
				wpaylsize = old_ao.paylsize;
			}
		}
	} else {
		wsecret = secret;
		wsecsize = secsize;
		wpayload = payload;
		wpaylsize = paylsize;
	}


	new_ao = make_authobj(userid, password, newnonce,
				wsecret, wsecsize, wpayload, wpaysize);

	if (old_ao.data) memset(old_ao.data, 0, old_ao.datasize);
	if (old_ao.payload) memset(old_ao.payload, 0, old_ao.paylsize);
	if (old_ao.buffer) free(old_ao.buffer);
	return new_ao;
}

void dummy() {
	struct _auth_chunk ho_chal, ho_key;

	ho_chal = make_challenge(userid, password, oldnonce);
	if (ho_chal.err) {
		new_ao.err = ho_chal.err;
		return new_ao;
	}
	ho_key = (*fetch_key)(ho_chal.hash, sizeof(ho_chal.hash));
	memset(&ho_chal, 0, sizeof(ho_chal));
	if (ho_key.err) {
		new_ao.err = ho_key.err;
		return new_ao;
	}
	old_ao = parse_authobj(ho_key.hash, sizeof(ho_key.hash),
				authobj, authsize);
	memset(&ho_key, 0, sizeof(ho_key));
	if (old_ao.err) {
		new_ao.err = old_ao.err;
		if (old_ao.buffer) free(old_ao.buffer);
		return new_ao;
	}

	ho_chal = make_challenge(userid, password, newnonce);
	if (ho_chal.err) {
		new_ao.err = ho_chal.err;
		return new_ao;
	}
	ho_key = make_key(ho_chal.hash, sizeof(ho_chal.hash),
				old_ao.data, old_ao.datasize);
	memset(&ho_chal, 0, sizeof(ho_chal));
	if (ho_key.err) {
		new_ao.err = ho_key.err;
		return new_ao;
	}
	new_ao = make_authobj(ho_key.hash, sizeof(ho_key.hash),
			old_ao.data, old_ao.datasize,
			old_ao.payload, old_ao.paylsize);
	memset(&ho_key, 0, sizeof(ho_key));

}
