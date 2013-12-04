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

#ifndef _TOKEN_H
#define _TOKEN_H

#include <winscard.h>

extern SCARD_IO_REQUEST pioSendPci;

struct token_interface {
	char *name;
	int (*parse_option)(char *key, char *val);
	DWORD (*check_atr_hb)(BYTE *str, DWORD size);
	DWORD (*prologue)(SCARDHANDLE hCard);
	DWORD (*getserial)(SCARDHANDLE hCard, BYTE *recv, LPDWORD recvsize_p);
	DWORD (*trancieve)(SCARDHANDLE hCard,
		BYTE *send, DWORD sendsize, BYTE *recv, LPDWORD recvsize_p);
	DWORD (*epilogue)(SCARDHANDLE hCard);
};

#endif
