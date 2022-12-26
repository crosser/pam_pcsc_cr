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
#include "base64.h"

static unsigned char src[40] = "Quick brown fox jumps over the lazy dog";

int main(int argc, char *argv[])
{
	int rc;
	char b64[57];  /* Must be: ((ssize-1)/3+1)*4+1) = 57 */
	char unsigned dst[42];  /* Must be: strlen(b64)*3/4 = 42 */
	int bsize, dsize;

	printf("src=\"%s\" (%lu/%d)\n", src, strlen((char *)src), (int)sizeof(src));
	bsize = sizeof(b64);
	if (b64_encode(src, sizeof(src), b64, &bsize)) {
		fprintf(stderr, "encode error\n");
		return 1;
	}
	printf("b64=\"%s\" (%lu/%d)\n", b64, strlen(b64), bsize);
	dsize = sizeof(dst);
	if ((rc = b64_decode(b64, dst, &dsize))) {
		fprintf(stderr, "decode error, rc=%d\n", rc);
		return 1;
	}
	printf("dst=\"%s\" (%lu/%d)\n", dst, strlen((char *)dst), dsize);
	return !(dsize == sizeof(src) && !memcmp(src, dst, dsize));
}
