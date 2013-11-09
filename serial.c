#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <string.h>
#include "serial.h"

void serial_init(serializer_t *srl, void *buffer, int size)
{
	srl->buffer = srl->cursor = buffer;
	srl->bufsize = size;
}

void serial_switch(serializer_t *srl, void *buffer, int size)
{
	int used = srl->cursor - srl->buffer;

	memcpy(buffer, srl->buffer, used);
	srl->buffer = buffer;
	srl->bufsize = size;
	srl->cursor = buffer + used;
}

int serial_put(serializer_t *srl, const void *item, int size)
{
	int left = srl->bufsize - (srl->cursor - srl->buffer);

	if (left < size + sizeof(short)) return left - sizeof(short);
	*((short *)srl->cursor) = size;
	srl->cursor += sizeof(short);
	if (size) memcpy(srl->cursor, item, size);
	srl->cursor += size;
	return size;
}

int serial_get(serializer_t *srl, void *item, int bufsize)
{
	int left = srl->bufsize - (srl->cursor - srl->buffer);
	short isize = *((short *)srl->cursor);

	if (isize > bufsize) return isize;
	if (isize + sizeof(short) > left) return -1;
	srl->cursor += sizeof(short);
	if (isize) memcpy(item, srl->cursor, isize);
	srl->cursor += isize;
	return isize;
}

int serial_size(serializer_t *srl)
{
	return srl->cursor - srl->buffer;
}
