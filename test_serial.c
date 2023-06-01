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

#include <stdio.h>
#include <string.h>
#include "serial.h"

int main(int argc, char *argv[])
{
	char *in[] = {
		"My",
		"Little",
		"Pony",
		NULL,
	};
	char buffer[256];
	int i, rc;
	serializer_t srl;

	serial_init(&srl, buffer, sizeof(buffer));
	for (i = 0; in[i]; i++) {
		int size = strlen(in[i]);
		if ((rc = serial_put(&srl, in[i], size)) != size) {
			printf("serial_put(..., \"%s\", %d) = %d\n",
				in[i], size, rc);
			return 1;
		}
	}
	if ((rc = serial_put(&srl, NULL, 0)) != 0) {
		printf("serial_put(..., NULL, 0) = %d\n", rc);
		return 1;
	}
	printf("serialized size=%d\n", (int)serial_size(&srl));
	serial_init(&srl, buffer, sizeof(buffer));
	for (i = 0; i < 4; i++) {
		char *item;
		size_t size;
		if (serial_get(&srl, (void**)&item, &size)) {
			printf("serial_get failed for item %d\n", i);
			rc = 1;
		} else {
			printf("serial_get(...) = %d: \"%.*s\"\n", (int)size, (int)size, item);
			if (memcmp(in[i], item, size)) {
				printf("\"%s\" != \"%s\" (%d)\n",
					in[i], item, (int)size);
				rc = 1;
			}
		}
	}
	return rc;
}
