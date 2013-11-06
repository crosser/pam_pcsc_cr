#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include "serial.h"
#include "crypto.h"
#include "authobj.h"

int make_authobj(const char *id, const char *pass, const char *nonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize,
		unsigned char *buffer, int *bufsize)
{
	unsigned char *data;
	int datasize;
	unsigned char datahash[HASHSIZE];
	int datahashsize = HASHSIZE;
	unsigned char *hmacdata;
	int hmacdatasize;
	unsigned char key[HASHSIZE];
	int keysize = HASHSIZE;
	serializer_t srl;

	datasize = ((secsize + paysize + HASHSIZE * 4 * sizeof(short) - 1) /
			CBLKSIZE + 1) * CBLKSIZE;
	data = alloca(datasize);
	if (serial_init(&srl, data, datasize)) return -1;
	if (serial_put(&srl, secret, secsize) != secsize) return -1;
	if (serial_put(&srl, payload, paysize) != paysize) return -1;
	if (hash(data, serial_size(&srl), datahash, &datahashsize))
		return -1;
	if (serial_put(&srl, datahash, datahashsize) != datahashsize)
		return -1;
	if (serial_put(&srl, NULL, 0) != 0) return -1;
	datasize = ((serial_size(&srl) -1) / CBLKSIZE + 1) * CBLKSIZE;

	hmacdatasize = ((strlen(id) + strlen(pass) + strlen(nonce) +
			4 * sizeof(short) - 1) / CBLKSIZE + 1) * CBLKSIZE;
	hmacdata = alloca(hmacdatasize);
	if (serial_init(&srl, hmacdata, hmacdatasize)) return -1;
	if (serial_put(&srl, id, strlen(id)) != strlen(id)) return -1;
	if (serial_put(&srl, pass, strlen(pass)) != strlen(pass)) return -1;
	if (serial_put(&srl, nonce, strlen(nonce)) != strlen(nonce)) return -1;
	if (serial_put(&srl, NULL, 0) != 0) return -1;
	hmacdatasize = ((serial_size(&srl) -1) / CBLKSIZE + 1) * CBLKSIZE;

	if (hmac(secret, secsize, hmacdata, hmacdatasize,
		key, &keysize)) return -1;

	if (*bufsize < datasize) return -1;
	*bufsize = datasize;
	if (encrypt(key, keysize, data, buffer, datasize)) return -1;

	return 0;
}

int parse_authobj(const unsigned char *hmacdata, const int hmacdatasize,
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

	if (decrypt(hmacdata, hmacdatasize, buffer, data, datasize))
		return -1;
	if (serial_init(&srl, data, datasize)) return -1;
	tsize = *secsize;
	if ((*secsize = serial_get(&srl, secret, tsize)) > tsize) return -1;
	tsize = *paysize;
	if ((*paysize = serial_get(&srl, payload, tsize)) > tsize) return -1;
	if (hash(data, serial_size(&srl), myhash, &myhashsize))
		return -1;
	if ((theirhashsize = serial_get(&srl, theirhash, theirhashsize)) != HASHSIZE)
		return -1;
	if ((myhashsize != theirhashsize) ||
				memcmp(myhash, theirhash, myhashsize))
		return -1;
	return 0;
}
