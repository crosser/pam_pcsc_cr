/*
Copyright (c) 2013 Eugene Crosser

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must
    not claim that you wrote the original software. If you use this
    software in a product, an acknowledgment in the product documentation
    would be appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must
    not be misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <alloca.h>
#include "serial.h"
#include "crypto.h"
#include "authobj.h"

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
new_key(const unsigned char *challenge, const int challengesize,
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

static struct _auth_chunk
make_key(const char *userid, const char *password, const char *nonce,
	const unsigned char *secret, const int secsize,
	struct _auth_chunk (*fetch_key)(const unsigned char *chal,
					const int csize))
{
	struct _auth_chunk ho_chal, ho_key = {0};

	if (!userid || !password || !nonce) {
		ho_key.err = "make_key: missing uid, pass or nonce";
		return ho_key;
	}
	ho_chal = make_challenge(userid, password, nonce);
	if (ho_chal.err) {
		ho_key.err = ho_chal.err;
		return ho_key;
	}
	if (secret && secsize) {
		ho_key = new_key(ho_chal.data, sizeof(ho_chal.data),
				secret, secsize);
	} else if (fetch_key) {
		ho_key = (*fetch_key)(ho_chal.data, sizeof(ho_chal.data));
	} else {
		ho_key.err = "make_key: neither secret nor fetch_key present";
	}
	memset(&ho_chal, 0, sizeof(ho_chal));
	return ho_key;
}

static struct _auth_obj
make_authobj(const char *userid, const char *password, const char *nonce,
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

	datasize = ((secsize + paylsize + HASHSIZE + 4 * sizeof(short) - 1) /
			CBLKSIZE + 1) * CBLKSIZE;
	data = alloca(datasize);
	/* 
	   We allocate memory rounded up to CBLKSIZE on the stack, but do not
	   use the last bytes. Stack protectors, if enabled, fill this memory
	   with `canary` value. Later, when encryption function is called,
	   stack protector detects that it tries to access "uninitialized
	   memory". Which, while technically true, is not an error. Still,
	   let us make stack protector happy by initializing the whole area:
	 */
	memset(data, 0, datasize);
	serial_init(&srl, data, datasize);
	if (serial_put(&srl, secret, secsize) != secsize) {
		ao.err = "authobj: serialization of secret failed";
	} else if (serial_put(&srl, payload, paylsize) != paylsize) {
		ao.err = "authobj: serialization of payload failed";
	} else if ((rc = hash(data, serial_size(&srl),
				datahash, &datahashsize))) {
		ao.err = crypto_errstr(rc);
	} else if (serial_put(&srl, datahash, datahashsize) != datahashsize) {
		ao.err = "authobj: serialization of hash failed";
	} else if (serial_put(&srl, NULL, 0) != 0) {
		ao.err = "authobj: serialization of terminator failed";
	} else {
		unsigned long lrc;
		int osize = ((serial_size(&srl) -1) / CBLKSIZE + 1) * CBLKSIZE;
		struct _auth_chunk ho_key;

		ho_key = make_key(userid, password, nonce,
					secret, secsize, NULL);
		if (ho_key.err) {
			ao.err = ho_key.err;
		} else if ((ao.buffer = malloc(osize + paylsize)) == NULL) {
			ao.err = "make authobj: malloc failed";
		} else if ((lrc = encrypt(ho_key.data, CBLKSIZE, data,
					ao.buffer, osize))) {
			ao.err = crypto_errstr(lrc);
		} else {
			ao.data = ao.buffer;
			ao.datasize = osize;
			if (payload && paylsize) {
				/* payload passthrough */
				ao.payload = ao.data + osize;
				memcpy(ao.payload, payload, paylsize);
				ao.paylsize = paylsize;
			}
		}
		memset(&ho_key, 0, sizeof(ho_key));
	}
	memset(data, 0, datasize);
	return ao;
}

static struct _auth_obj
parse_authobj(const char *userid, const char *password, const char *nonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *ablob, const int blobsize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize))
{
	unsigned long rc;
	struct _auth_obj ao = {0};
	struct _auth_chunk ho_key;

	ho_key = make_key(userid, password, nonce, secret, secsize, fetch_key);
	if (ho_key.err) {
		ao.err = ho_key.err;
	} else if ((ao.buffer = malloc(blobsize)) == NULL) {
		ao.err = "parse authobj: malloc failed";
	} else if ((rc = decrypt(ho_key.data, CBLKSIZE,
				ablob, ao.buffer, blobsize))) {
		ao.err = crypto_errstr(rc);
	} else {
		serializer_t srl;
		unsigned char myhash[HASHSIZE];
		int myhsize = HASHSIZE;
		unsigned char *theirhash;
		int theirhsize;
		unsigned long rc;

		serial_init(&srl, ao.buffer, blobsize);
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
	memset(&ho_key, 0, sizeof(ho_key));
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
	const unsigned char *wsecret;
	int wsecsize;
	const unsigned char *wpayload;
	int wpaylsize;
	struct _auth_obj old_ao = {0};
	struct _auth_obj new_ao = {0};

	if (!secret || !secsize || !payload) {
		if (!ablob || !blobsize) {
			new_ao.err = "authobj: previous data not supplied";
			return new_ao;
		}
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
				wsecret, wsecsize, wpayload, wpaylsize);

	if (old_ao.data) memset(old_ao.data, 0, old_ao.datasize);
	if (old_ao.payload) memset(old_ao.payload, 0, old_ao.paylsize);
	if (old_ao.buffer) free(old_ao.buffer);
	return new_ao;
}
