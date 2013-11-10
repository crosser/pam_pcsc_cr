#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <alloca.h>
#include "authobj.h"
#include "authfile.h"
#include "pcsc_cr.h"

#define OBJSIZE 256

int update_authfile(const char *fn, const char *tokenid, const char *id,
                const char *password, const char *nonce,
                const unsigned char *secret, const int secsize,
                const unsigned char *payload, const int paysize)
{
	FILE *fp;
	int rc;
	int i;
	unsigned char key[20];
	int keysize = sizeof(key);
	unsigned char mysecret[20];
	int mysecsize = sizeof(mysecret);
	unsigned char myload[256];
	int myloadsize = sizeof(myload);
	unsigned char *authobj = alloca(OBJSIZE);
	int authsize = OBJSIZE;
	char buf[512];
	char *oldtokenid = NULL, *oldid = NULL, *oldnonce = NULL,
		*hauthobj = NULL;
	unsigned char *oldauthobj = NULL;
	int oldauthsize;

	if ((fp = fopen(fn, "r"))) {
		if (fgets(buf, sizeof(buf), fp)) {
			oldtokenid = strtok(buf, ":\r\n");
			oldid = strtok(NULL, ":\r\n");
			oldnonce = strtok(NULL, ":\r\n");
			hauthobj = strtok(NULL, ":\r\n");
		} else {
			eprint("error reading from %s: %s",
				fn, strerror(errno));
		}
		fclose(fp);
	}
	if (hauthobj) {
		int hlen;

		hlen = strlen(hauthobj);
		if (hlen % 32 != 0) {
			eprint("error: auth string has wrong length");
		} else if (hlen !=
				strspn(hauthobj, "0123456789abcdefABCDEF")) {
			eprint("error: auth string not hexadecimal");
		} else {
			oldauthsize = hlen/2;
			oldauthobj = alloca(oldauthsize);
			for (i = 0; i < oldauthsize; i++)
				sscanf(&hauthobj[i*2], "%2hhx", &oldauthobj[i]);
		}
	}

	if (oldauthobj && password && !secret) {
		unsigned char chal[64];
		int csize = sizeof(chal);
		long rc;

		rc = make_challenge(id, password, nonce, chal, &csize);
		if (rc) {
			eprint("cannot make challenge");
			return -1;
		}
		rc = pcsc_cr(chal, csize, key, &keysize);
		if (rc) {
			eprint("error querying token: %s", pcsc_errstr(rc));
			return -1;
		}
		rc = parse_authobj(key, keysize, oldauthobj, oldauthsize,
			mysecret, &mysecsize, myload, &myloadsize);
		if (rc) {
			eprint("cannot parse old authobj: %d", rc);
			return -1;
		}
	}

	rc = make_authobj(id, password, nonce, mysecret, mysecsize,
			payload, paysize, authobj, &authsize);
	if (rc) {
		eprint("make_authobj error %d", rc);
		return -1;
	}
	fp = fopen(fn, "w");
	if (!fp) {
		eprint("cannot open \"%s\": %s",
			fn, strerror(errno));
		return -1;
	}
	if (fprintf(fp, "%s:%s:%s:", tokenid, id, nonce) < 0) {
		eprint("cannot write to \"%s\": %s",
			fn, strerror(errno));
		return -1;
	}
	for (i = 0; i < authsize; i++)
	    if (fprintf(fp, "%02x", authobj[i]) < 0) {
		eprint("cannot write to \"%s\": %s",
			fn, strerror(errno));
		return -1;
	}
	fprintf(fp, "\n");
	if (fclose(fp) < 0) {
		eprint("cannot close \"%s\": %s",
			fn, strerror(errno));
		return -1;
	}
	return 0;
}
