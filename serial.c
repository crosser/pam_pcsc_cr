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

/* returns 'size' on success, or remainging space if it was insufficient */
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

/* return 0 on success, -1 on wrong encoding (item longer than space left) */
int serial_get(serializer_t *srl, void **item, int *size)
{
	int left = srl->bufsize - (srl->cursor - srl->buffer);
	short isize = *((short *)srl->cursor);

	if (isize + sizeof(short) > left) return -1;
	srl->cursor += sizeof(short);
	*item = srl->cursor;
	*size = isize;
	srl->cursor += isize;
	return 0;
}

int serial_size(serializer_t *srl)
{
	return srl->cursor - srl->buffer;
}
