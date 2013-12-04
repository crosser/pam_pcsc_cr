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
int serial_get(serializer_t *srl, void **item, int *size);
int serial_size(serializer_t *srl);

#endif
