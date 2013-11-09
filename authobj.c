#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include "serial.h"
#include "crypto.h"
#include "authobj.h"

int make_challenge(const char *id, const char *pass, const char *nonce,
		unsigned char *challenge, int *challengesize)
{
	serializer_t srl;

	serial_init(&srl, challenge, *challengesize);
	if (serial_put(&srl, id, strlen(id)) != strlen(id))
		return aoe_serial;
	if (serial_put(&srl, pass, strlen(pass)) != strlen(pass))
		return aoe_serial;
	if (serial_put(&srl, nonce, strlen(nonce)) != strlen(nonce))
		return aoe_serial;
	if (serial_put(&srl, NULL, 0) != 0)
		return aoe_serial;
	*challengesize = serial_size(&srl);
	return 0;
}

int make_authobj(const char *id, const char *pass, const char *nonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize,
		unsigned char *buffer, int *bufsize)
{
	unsigned char *data;
	int datasize;
	unsigned char datahash[HASHSIZE];
	int datahashsize = HASHSIZE;
	unsigned char *challenge;
	int challengesize;
	unsigned char key[HASHSIZE];
	int keysize = HASHSIZE;
	serializer_t srl;

	datasize = ((secsize + paysize + HASHSIZE * 4 * sizeof(short) - 1) /
			CBLKSIZE + 1) * CBLKSIZE;
	data = alloca(datasize);
	serial_init(&srl, data, datasize);
	if (serial_put(&srl, secret, secsize) != secsize) return aoe_serial;
	if (serial_put(&srl, payload, paysize) != paysize) return aoe_serial;
	if (hash(data, serial_size(&srl), datahash, &datahashsize))
		return aoe_size;
	if (serial_put(&srl, datahash, datahashsize) != datahashsize)
		return aoe_serial;
	if (serial_put(&srl, NULL, 0) != 0) return aoe_serial;
	datasize = ((serial_size(&srl) -1) / CBLKSIZE + 1) * CBLKSIZE;

	challengesize = ((strlen(id) + strlen(pass) + strlen(nonce) +
			4 * sizeof(short) - 1) / CBLKSIZE + 1) * CBLKSIZE;
	challenge = alloca(challengesize);
	if (make_challenge(id, pass, nonce, challenge, &challengesize))
		return aoe_serial;

	if (hmac(secret, secsize, challenge, challengesize,
		key, &keysize)) return aoe_crypt;

	if (*bufsize < datasize) return aoe_size;
	if (encrypt(key, CBLKSIZE, data, buffer, datasize)) return aoe_crypt;
	*bufsize = datasize;

	return 0;
}

int parse_authobj(const unsigned char *key, const int keysize,
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
		return aoe_crypt;
	serial_init(&srl, data, datasize);
	tsize = *secsize;
	*secsize = serial_get(&srl, secret, tsize);
	if (*secsize > tsize || *secsize <= 0) return aoe_serial;
	tsize = *paysize;
	*paysize = serial_get(&srl, payload, tsize);
	if (*paysize > tsize || *paysize <= 0) return aoe_serial;
	if (hash(data, serial_size(&srl), myhash, &myhashsize))
		return aoe_crypt;
	theirhashsize = serial_get(&srl, theirhash, theirhashsize);
	if (theirhashsize != HASHSIZE) return aoe_data;
	if ((myhashsize != theirhashsize) ||
	    memcmp(myhash, theirhash, myhashsize))
		return aoe_data;
	return 0;
}
