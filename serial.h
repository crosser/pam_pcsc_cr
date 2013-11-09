#ifndef _SERIAL_H
#define _SERIAL_H

typedef struct _serializer {
	char *buffer;
	int bufsize;
	char *cursor;
} serializer_t;

void serial_init(serializer_t *srl, void *buffer, int size);
void serial_switch(serializer_t *srl, void *buffer, int size);
int serial_put(serializer_t *srl, const void *item, int size);
int serial_get(serializer_t *srl, void *item, int bufsize);
int serial_size(serializer_t *srl);

#endif
