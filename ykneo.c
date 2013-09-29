#include <string.h>
#include <alloca.h>

#include "token.h"

#define NAMEPFX "YubikeyNEO"

static const BYTE selcmd[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0,
				0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00};
static const BYTE cr_cmd[] = {0x00, 0x01, 0x38, 0x00};

static DWORD ykn_check_atr_hb(LPTSTR str, DWORD size)
{
	if (size < strlen(NAMEPFX)) return SCARD_W_UNSUPPORTED_CARD;
	if (memcmp(str, NAMEPFX, strlen(NAMEPFX)))
		return SCARD_W_UNSUPPORTED_CARD;
	return SCARD_S_SUCCESS;
}

static DWORD ykn_prologue(SCARDHANDLE hCard,LPTSTR envp[])
{
	BYTE buf[258];
	DWORD rsize = sizeof(buf);
	DWORD rc = SCardBeginTransaction(hCard);
	if (rc) return rc;
	rc = SCardTransmit(hCard, &pioSendPci, selcmd, sizeof(selcmd),
		NULL, buf, &rsize);
	if (rc) return rc;
	if ((buf[rsize-2] == 0x90) && (buf[rsize-1] == 0x00))
		return SCARD_S_SUCCESS;
	else return SCARD_W_CARD_NOT_AUTHENTICATED;
}

static DWORD ykn_trancieve(SCARDHANDLE hCard,LPTSTR envp[],
	LPTSTR send, DWORD sendsize, LPTSTR recv, LPDWORD recvsize_p)
{
	DWORD rc;
	DWORD rsize = *recvsize_p + 2;
	BYTE *rbuf = alloca(rsize);
	BYTE *sbuf = alloca(sendsize + 6);
	memcpy(sbuf, cr_cmd, sizeof(cr_cmd));
	sbuf[sizeof(cr_cmd)] = sendsize;
	memcpy(sbuf + sizeof(cr_cmd) + 1, send, sendsize);
	sbuf[sendsize + 5] = rsize;
	rc = SCardTransmit(hCard, &pioSendPci, sbuf, sendsize + 6,
		NULL, rbuf, &rsize);
	if (rc) return rc;
	if ((rbuf[rsize-2] != 0x90) || (rbuf[rsize-1] != 0x00))
		return SCARD_W_CARD_NOT_AUTHENTICATED;
	memcpy(recv, rbuf, rsize - 2);
	*recvsize_p = rsize - 2;
	return SCARD_S_SUCCESS;
}

static DWORD ykn_epilogue(SCARDHANDLE hCard,LPTSTR envp[])
{
	return SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
}

struct token_interface ykneo_interface = {
	.check_atr_hb	= ykn_check_atr_hb,
	.prologue	= ykn_prologue,
	.trancieve	= ykn_trancieve,
	.epilogue	= ykn_epilogue,
};
