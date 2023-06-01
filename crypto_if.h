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

#ifndef _CRYPTO_IF_H
#define _CRYPTO_IF_H

struct crypto_interface {
	const char *(*init)(void);
	unsigned long (*encrypt)(const void *key, const size_t keylen, void *iv,
				const void *pt, void *ct, const size_t tlen);
	unsigned long (*decrypt)(const void *key, const size_t keylen, void *iv,
				const void *ct, void *pt, const size_t tlen);
	unsigned long (*hash)(const void *pt, const size_t tlen,
				void *tag, size_t *taglen);
	unsigned long (*hmac)(const void *key, const size_t keylen,
				const void *pt, const size_t tlen,
				void *tag, size_t *taglen);
	const char *(*errstr)(const unsigned long err);
};

#endif
