#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <string.h>
#include "serial.h"

int serial_init(serializer_t *srl, void *buffer, int size)
{
	srl->buffer = srl->cursor = buffer;
	srl->bufsize = size;
	return 0;
}

int serial_switch(serializer_t *srl, void *buffer, int size)
{
	int used = srl->cursor - srl->buffer;

	memcpy(buffer, srl->buffer, used);
	srl->buffer = buffer;
	srl->bufsize = size;
	srl->cursor = buffer + used;
	return 0;
}

int serial_put(serializer_t *srl, const void *item, int size)
{
	int left = srl->bufsize - (srl->cursor - srl->buffer);
	if (left < size + sizeof(short)) return left - sizeof(short);
	*((short *)srl->cursor) = size;
	srl->cursor += 2;
	if (size) memcpy(srl->cursor, item, size);
	srl->cursor += size;
	return size;
}

int serial_get(serializer_t *srl, void *item, int bufsize)
{
	short isize = *((short *)srl->cursor);
	if (isize > bufsize || isize == 0) return isize;
	srl->cursor += sizeof(short);
	memcpy(item, srl->cursor, isize);
	srl->cursor += isize;
	return isize;
}

int serial_size(serializer_t *srl)
{
	return srl->cursor - srl->buffer;
}
