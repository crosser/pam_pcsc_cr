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
	printf("serialized size=%d\n", serial_size(&srl));
	serial_init(&srl, buffer, sizeof(buffer));
	for (i = 0; i < 4; i++) {
		char item[32];
		memset(item, 0, sizeof(item));
		int size = serial_get(&srl, item, sizeof(item));
		if (size > sizeof(item)) {
			printf("serial_get(..., item, %d) = %d\n",
				(int)sizeof(item), size);
			rc = 1;
		} else if (size == 0) {
			printf("serial_get(...) = 0\n");
		} else {
			printf("serial_get(...) = %d: \"%s\"\n", size, item);
			if (memcmp(in[i], item, size)) {
				printf("\"%s\" != \"%s\" (%d)\n",
					in[i], item, size);
				rc = 1;
			}
		}
	}
	return rc;
}
