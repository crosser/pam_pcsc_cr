#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include "authfile.h"
#include "pcsc_cr.h"

int eprint(const char *format, ...)
{
	va_list ap;
	char *nfmt;

	nfmt = alloca(strlen(format)+2);
	strcpy(nfmt, format);
	strcat(nfmt, "\n");
	va_start(ap, format);
	return vfprintf(stderr, nfmt, ap);
	va_end(ap);
}

static void usage(const char const *cmd)
{
	eprint(	"usage: %s [options] [username]\n"
		"    -h                - show this help and exit\n"
		"    -o backend-option - token option \"backend:key=val\"\n"
		"    -f auth-file      - auth state file to read/write\n"
		"    -a secret | -A file-with-secret | -A -\n"
		"                      - 40-character hexadecimal secret\n"
		"    -s token-serial   - public I.D. of the token\n"
		"    -n nonce          - initial nonce\n"
		"    -l payload        - keyring unlock password\n"
		"    -p password       - login password"
		, cmd);
}

int main(int argc, char *argv[])
{
	int c;
	char *fn = NULL;
	char *hsecret = NULL;
	char *secfn = NULL;
	char secbuf[43];
	unsigned char bsecret[20];
	unsigned char *secret = NULL;
	int i;
	char *nonce = NULL;
	char *tokenid = NULL;
	char *id = getlogin();
	char *payload = "";
	char *password = "";

	while ((c = getopt(argc, argv, "ho:f:a:A:s:n:l:p:")) != -1)
	    switch (c) {
	case 'h':
		usage(argv[0]);
		exit(EXIT_SUCCESS);
	case 'o':
		if (pcsc_option(optarg)) {
			eprint("Option \"%s\" bad", optarg);
			exit(EXIT_FAILURE);
		}
		break;
	case 'f':
		fn = optarg;
		break;
	case 'a':
		if (!secfn) {
			hsecret = optarg;
		} else {
			eprint("-a and -A are mutually exclusive");
			exit(EXIT_FAILURE);
		}
		break;
	case 'A':
		if (!hsecret) {
			secfn = optarg;
		} else {
			eprint("-A and -a are mutually exclusive");
			exit(EXIT_FAILURE);
		}
		break;
	case 's':
		tokenid = optarg;
		break;
	case 'n':
		nonce = optarg;
		break;
	case 'l':
		payload = optarg;
		break;
	case 'p':
		password = optarg;
		break;
	default:
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (optind == (argc - 1)) {
		id = argv[optind];
		optind++;
	}
	if (optind != argc) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (secfn) {
		FILE *sfp;
		char *p;

		if (!strcmp(secfn, "-")) sfp = stdin;
		else sfp = fopen(secfn, "r");
		if (!sfp) {
			eprint("cannot open \"%s\": %s",
				secfn, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (!fgets(secbuf, sizeof(secbuf), sfp)) {
			eprint("cannot read \"%s\": %s",
				secfn, strerror(errno));
			exit(EXIT_FAILURE);
		}
		for (p = secbuf + strlen(secbuf) - 1;
			*p == '\n' || *p == '\r'; p--) *p = '\n';

		fclose(sfp);
		hsecret = secbuf;
	}
	if (!id) {
		eprint("cannot determine userid");
		exit(EXIT_FAILURE);
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
	return update_authfile(fn, tokenid, id, password, nonce,
				secret, sizeof(bsecret),
				(unsigned char *)payload, strlen(payload));
}
