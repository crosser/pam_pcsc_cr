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
#include <unistd.h>
#include <string.h>
#include "pcsc_cr.h"

static void usage(const char const *cmd)
{
	fprintf(stderr,
		"usage: %s [-o backend:name=value] ... \"challenge\"\n",
		cmd);
}

int main(int argc, char *argv[])
{
	unsigned char chal[64];
	int csize;
	unsigned char rbuf[20];
	int rsize = sizeof(rbuf);
	int i;
	long rc;
	int c;

	while ((c = getopt(argc, argv, "ho:")) != -1) switch (c) {
	case 'h':
		usage(argv[0]);
		exit(0);
	case 'o':
		if (pcsc_option(optarg)) {
			fprintf(stderr, "Option \"%s\" bad\n", optarg);
			exit(1);
		}
		break;
	default:
		usage(argv[0]);
		exit(1);
	}
	if (optind != (argc - 1)) {
		usage(argv[0]);
		exit(1);
	}

	csize = strlen(argv[optind]);
	if (csize > sizeof(chal)) {
		fprintf(stderr, "Challenge longer than %d, cannot do that\n",
			csize);
		exit(1);
	}
#if 0
	printf("\nIf the key is set to \"Jefe\" like this:\n"
	"$ ykpersonalize -2 -o chal-resp -o chal-hmac -o hmac-lt64 \\\n"
	"\t-a 4a65666500000000000000000000000000000000\n"
	"and the challenge is \"what do ya want for nothing?\"\n"
	"the result must be                  "
	"\"ef fc df 6a e5 eb 2f a2 d2 74 16 d5 f1 84 df 9c 25 9a 7c 79\"\n");
#endif
	memset(chal, 0x00, sizeof(chal));
	memcpy(chal, argv[optind], csize);
	
	memset(rbuf, 0xFE, sizeof(rbuf));
	rc = pcsc_cr(chal, csize, rbuf, &rsize);
	printf("rc=%ld (%s) rsize=%d:", rc, pcsc_errstr(rc), rsize);
	for (i = 0; i < rsize; i++) printf(" %02x", rbuf[i]);
	printf("\n");
	return rc;
}
