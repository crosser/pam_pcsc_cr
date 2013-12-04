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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include "authobj.h"
#include "authfile.h"
#include "pcsc_cr.h"

static struct _auth_chunk
token_key(const unsigned char *challenge, const int challengesize)
{
	struct _auth_chunk ho = {0};
	long rc;
	int keysize = sizeof(ho.data);

	if ((rc = pcsc_cr(challenge, challengesize, ho.data, &keysize))) {
		ho.err = pcsc_errstr(rc);
	}
	return ho;
}

static char *mynonce = NULL;

static void update_nonce(char *nonce, const int nonsize)
{
	if (mynonce) {
		snprintf(nonce, nonsize, "%s", mynonce);
	} else {
		int n = 0;

		sscanf(nonce, "%d", &n);
		snprintf(nonce, nonsize, "%d", n+1);
	}
}

static void usage(const char * const cmd)
{
	fprintf(stderr,
		"usage: %s [options] [username]\n"
		"    -h                - show this help and exit\n"
		"    -o backend-option - token option \"backend:key=val\"\n"
		"    -f template       - template for auth state filepath\n"
		"    -a secret | -A file-with-secret | -A -\n"
		"                      - 40-character hexadecimal secret\n"
		"    -s token-serial   - public I.D. of the token\n"
		"    -n nonce          - initial nonce\n"
		"    -l payload        - keyring unlock password\n"
		"    -p password       - login password\n"
		"    -v                - show returned data\n"
		, cmd);
}

int main(int argc, char *argv[])
{
	struct _auth_obj ao;
	int c;
	int verbose = 0;
	char *hsecret = NULL;
	char *secfn = NULL;
	char secbuf[43];
	unsigned char bsecret[20];
	unsigned char *secret = NULL;
	int i;
	char *tokenid = NULL;
	char *userid = getlogin();
	char *payload = NULL;
	char *password = "";

	while ((c = getopt(argc, argv, "ho:f:a:A:s:n:l:p:v")) != -1)
	    switch (c) {
	case 'h':
		usage(argv[0]);
		exit(EXIT_SUCCESS);
	case 'o':
		if (pcsc_option(optarg)) {
			fprintf(stderr, "Option \"%s\" bad", optarg);
			exit(EXIT_FAILURE);
		}
		break;
	case 'f':
		authfile_template(optarg);
		break;
	case 'a':
		if (!secfn) {
			hsecret = optarg;
		} else {
			fprintf(stderr, "-a and -A are mutually exclusive");
			exit(EXIT_FAILURE);
		}
		break;
	case 'A':
		if (!hsecret) {
			secfn = optarg;
		} else {
			fprintf(stderr, "-A and -a are mutually exclusive");
			exit(EXIT_FAILURE);
		}
		break;
	case 's':
		tokenid = optarg;
		break;
	case 'n':
		mynonce = optarg;
		break;
	case 'l':
		payload = optarg;
		break;
	case 'p':
		password = optarg;
		break;
	case 'v':
		verbose = 1;
		break;
	default:
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (optind == (argc - 1)) {
		userid = argv[optind];
		optind++;
	}
	if (optind != argc) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (!userid) {
		fprintf(stderr, "cannot determine userid");
		exit(EXIT_FAILURE);
	}
	if (secfn) {
		FILE *sfp;
		char *p;

		if (!strcmp(secfn, "-")) sfp = stdin;
		else sfp = fopen(secfn, "r");
		if (!sfp) {
			fprintf(stderr, "cannot open \"%s\": %s",
				secfn, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (!fgets(secbuf, sizeof(secbuf), sfp)) {
			fprintf(stderr, "cannot read \"%s\": %s",
				secfn, strerror(errno));
			exit(EXIT_FAILURE);
		}
		for (p = secbuf + strlen(secbuf) - 1;
			*p == '\n' || *p == '\r'; p--) *p = '\n';

		fclose(sfp);
		hsecret = secbuf;
	}
	if (hsecret) {
		if (strlen(hsecret) != 40) {
			fprintf(stderr,
				"secret wrong, must be exactly 40 chars\n");
			exit(EXIT_FAILURE);
		}
		if (strspn(hsecret, "0123456789abcdefABCDEF") != 40) {
			fprintf(stderr,
				"secret wrong, must be hexadecimal string\n");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < 20; i++)
			sscanf(hsecret + i * 2, "%2hhx", &bsecret[i]);
		secret = bsecret;
	}
	ao = authfile(tokenid, userid, password, update_nonce,
			secret, secret ? sizeof(bsecret) : 0,
			(unsigned char *)payload, payload ? strlen(payload) : 0,
			token_key);
	memset(bsecret, 0, sizeof(bsecret));
	if (ao.err) {
		fprintf(stderr, "%s\n", ao.err);
		exit(EXIT_FAILURE);
	} else if (verbose) {
		printf("userid : \"%.*s\"\n", ao.datasize, ao.data);
		printf("payload: \"%.*s\"\n", ao.paylsize, ao.payload);
	}
	if (ao.buffer) free(ao.buffer);
	return 0;
}
