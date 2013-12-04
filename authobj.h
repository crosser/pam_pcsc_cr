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

#ifndef _AUTHOBJ_H
#define _AUTHOBJ_H

#define AUTHCHUNKSIZE 20

struct _auth_chunk {
	const char *err;
	unsigned char data[AUTHCHUNKSIZE];
};

struct _auth_obj {
	unsigned char *buffer;	/* to be free()'d if not NULL */
	const char *err;	/* non-NULL if failed */
	unsigned char *data;
	int datasize;
	unsigned char *payload;
	int paylsize;
};

/* Construct new or repack old authobj, return payload */
struct _auth_obj authobj(const char *userid, const char *password,
		const char *oldnonce, const char *newnonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize,
		const unsigned char *ablob, const int blobsize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize));

#endif
