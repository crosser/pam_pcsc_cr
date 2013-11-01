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
