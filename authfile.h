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

#ifndef _AUTHFILE_H
#define _AUTHFILE_H

void authfile_template(const char *template);

struct _auth_obj authfile(const char *tokenid,
		const char *userid, const char *password,
		void (*update_nonce)(char *nonce, const int nonsize),
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize));

#endif
