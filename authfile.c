#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
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
	unsigned char *mysecret = secret;
	int mysecsize = secsize;
	unsigned char *myload = payload;
	int myloadsize = paysize;
	unsigned char *authobj = NULL;
	int authsize = 0;
	char *buf = NULL;
	char *mytokenid = NULL;
	char *myid = NULL;
	char *mynonce = NULL;
	char *hauthobj = NULL;
	unsigned char *oldauthobj = NULL;
	int oldauthsize;

	if ((fp = fopen(fn, "r"))) {
		struct stat st;
		int fd = fileno(fp);

		if (!fstat(fd, &st)) {
			eprint("fstat \"%s\" (fd %d) error: %s",
				fn, fd, strerror(errno));
			st.st_size = 2047;
		}
		if (st.st_size > 2047) st.st_size = 2047;
		buf = alloca(st.st_size + 1);
		if (fgets(buf, st.st_size + 1, fp)) {
			char *p;

			p = &buf[strlen(buf) - 1];
			while (*p == '\n' || *p == '\r') *p-- = '\0';
			mytokenid = strtok(buf, ":");
			myid = strtok(NULL, ":");
			mynonce = strtok(NULL, ":");
			hauthobj = strtok(NULL, ":");
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

	if (!secret) {
		unsigned char chal[64];
		int csize = sizeof(chal);
		long rc;

		if (!oldauthobj || !password) {
			eprint("if no secret given, old auth file must"
				" be present and password must be given");
			return -1;
		}
		rc = make_challenge(myid, password, mynonce, chal, &csize);
		if (rc) {
			eprint("cannot make challenge");
			return -1;
		}
		rc = pcsc_cr(chal, csize, key, &keysize);
		if (rc) {
			eprint("error querying token: %s", pcsc_errstr(rc));
			return -1;
		}
		mysecsize = oldauthsize;
		mysecret = alloca(mysecsize);
		myloadsize  = oldauthsize;
		myload = alloca(myloadsize);
		rc = parse_authobj(key, keysize, oldauthobj, oldauthsize,
			mysecret, &mysecsize, myload, &myloadsize);
		if (rc) {
			eprint("cannot parse old authobj: %d", rc);
			return -1;
		}
	}
	if (tokenid) mytokenid = tokenid;
	if (id) myid = id;
	if (nonce) mynonce = nonce;
	else {
		unsigned int prev = atoi(mynonce);
		mynonce = alloca(16);
		sprintf(mynonce, "%d", prev + 1);
	}

	authsize = ((mysecsize + myloadsize + 16 + 4 * sizeof(short) - 1) /
			16 + 1) * 16;
	authobj = alloca(authsize);
	rc = make_authobj(myid, password, mynonce, mysecret, mysecsize,
			myload, myloadsize, authobj, &authsize);
	if (rc) {
		eprint("make_authobj error %d", rc);
		return -1;
	}

	if ((fp = fopen(fn, "w"))) {
		if (fprintf(fp, "%s:%s:%s:", mytokenid, myid, mynonce) < 0) {
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
	} else {
		eprint("cannot open \"%s\": %s",
			fn, strerror(errno));
		return -1;
	}
	return 0;
}
