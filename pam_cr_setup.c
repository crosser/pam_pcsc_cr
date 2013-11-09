#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "authobj.h"
#if 0
#include "pcsc_cr.h"
#endif

static void usage(const char const *cmd)
{
	fprintf(stderr,
		"usage: %s [-f filename] {-s hexstring40 | -S file} [-u username] [-n nonce] [-l payload] [-p password]\n",
		cmd);
}

int main(int argc, char *argv[])
{
	int c;
	char *fn = NULL;
	FILE *fp;
	char *hsecret = NULL;
	char *secfn = NULL;
	char secbuf[43];
	unsigned char secret[20];
	int i;
	char *nonce = "1";
	char *id = getlogin();
	char *payload = "";
	char *password = "";
	int rc;
	unsigned char authobj[256];
	int authsize = sizeof(authobj);

	while ((c = getopt(argc, argv, "h"
#if 0
					"o:"
#endif
					"f:s:S:u:n:l:p:")) != -1) switch (c) {
	case 'h':
		usage(argv[0]);
		exit(EXIT_SUCCESS);
#if 0
	case 'o':
		if (pcsc_option(optarg)) {
			fprintf(stderr, "Option \"%s\" bad\n", optarg);
			exit(EXIT_FAILURE);
		}
		break;
#endif
	case 'f':
		fn = optarg;
		break;
	case 's':
		if (!secfn) {
			hsecret = optarg;
		} else {
			fprintf(stderr, "-s and -S are mutually exclusive\n");
			exit(EXIT_FAILURE);
		}
		break;
	case 'S':
		if (!hsecret) {
			secfn = optarg;
		} else {
			fprintf(stderr, "-S and -s are mutually exclusive\n");
			exit(EXIT_FAILURE);
		}
		break;
	case 'u':
		id = optarg;
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
	if (optind == (argc - 1) && !secfn && !hsecret) {
		hsecret = argv[optind];
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
			fprintf(stderr, "cannot open \"%s\": %s\n",
				secfn, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (!fgets(secbuf, sizeof(secbuf), sfp)) {
			fprintf(stderr, "cannot read \"%s\": %s\n",
				secfn, strerror(errno));
			exit(EXIT_FAILURE);
		}
		for (p = secbuf + strlen(secbuf) - 1;
			*p == '\n' || *p == '\r'; p--) *p = '\n';

		fclose(sfp);
		hsecret = secbuf;
	}
	if (!hsecret) {
		fprintf(stderr, "secret missing, specify -s or -S\n");
		exit(EXIT_FAILURE);
	}
	if (strlen(hsecret) != 40) {
		fprintf(stderr, "secret wrong, must be exactly 40 chars\n");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < 20; i++)
	    if (sscanf(hsecret + i * 2, "%2hhx", &secret[i]) != 1) {
		fprintf(stderr, "secret wrong, must be hexadecimal\n");
		exit(EXIT_FAILURE);
	}
	if (!id) {
		fprintf(stderr, "cannot determine userid\n");
		exit(EXIT_FAILURE);
	}
	rc = make_authobj(id, password, nonce, secret, sizeof(secret),
			(unsigned char *)payload, strlen(payload),
			authobj, &authsize);
	if (rc) {
		fprintf(stderr, "error %d\n", rc);
		exit(EXIT_FAILURE);
	}
	fp = fopen(fn, "w");
	if (!fp) {
		fprintf(stderr, "cannot open \"%s\": %s\n",
			fn, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (fprintf(fp, "%s:%s:%s:", "", id, nonce) < 0) {
		fprintf(stderr, "cannot write to \"%s\": %s\n",
			fn, strerror(errno));
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < authsize; i++)
	    if (fprintf(fp, "%02x", authobj[i]) < 0) {
		fprintf(stderr, "cannot write to \"%s\": %s\n",
			fn, strerror(errno));
		exit(EXIT_FAILURE);
	}
	fprintf(fp, "\n");
	if (fclose(fp) < 0) {
		fprintf(stderr, "cannot close \"%s\": %s\n",
			fn, strerror(errno));
		exit(EXIT_FAILURE);
	}
	return 0;
}
