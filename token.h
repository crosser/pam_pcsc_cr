#ifndef _TOKEN_H
#define _TOKEN_H

#include <winscard.h>

extern SCARD_IO_REQUEST pioSendPci;

struct token_interface {
	DWORD (*check_atr_hb)(LPTSTR str, DWORD size);
	DWORD (*prologue)(SCARDHANDLE hCard,LPTSTR envp[]);
	DWORD (*trancieve)(SCARDHANDLE hCard,LPTSTR envp[],
		LPTSTR send, DWORD sendsize, LPTSTR recv, LPDWORD recvsize_p);
	DWORD (*epilogue)(SCARDHANDLE hCard,LPTSTR envp[]);
};

#endif
