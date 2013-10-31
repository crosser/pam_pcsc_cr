#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

#include "token.h"

#define NAMEPFX "YubikeyNEO"

static const BYTE selcmd[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0,
				0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00};
static const BYTE cr_cmd[] = {0x00, 0x01, 0xff, 0x00};

static BYTE cr_for_slot[3] = {0xff, 0x30, 0x38};

static int slot = 2;	/* second by default, people tend to leave */
			/* the first with factory settings.        */

static int ykn_parse_option(char *key, char *val)
{
	if (!strcmp(key, "slot")) {
		if (!strcmp(val, "1")) {
			slot = 1;
		} else if (!strcmp(val, "2")) {
			slot = 2;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
	return 0;
}

static DWORD ykn_check_atr_hb(BYTE *str, DWORD size)
{
	if (size < strlen(NAMEPFX)) return SCARD_W_UNSUPPORTED_CARD;
	if (memcmp(str, NAMEPFX, strlen(NAMEPFX)))
		return SCARD_W_UNSUPPORTED_CARD;
	return SCARD_S_SUCCESS;
}

static DWORD ykn_prologue(SCARDHANDLE hCard)
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

static DWORD ykn_trancieve(SCARDHANDLE hCard,
	BYTE *send, DWORD sendsize, BYTE *recv, LPDWORD recvsize_p)
{
	DWORD rc;
	DWORD rsize = *recvsize_p + 2;
	BYTE *rbuf = alloca(rsize);
	BYTE *sbuf = alloca(sendsize + 6);
	memcpy(sbuf, cr_cmd, sizeof(cr_cmd));
	sbuf[2] = cr_for_slot[slot];
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

static DWORD ykn_epilogue(SCARDHANDLE hCard)
{
	return SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
}

struct token_interface ykneo_interface = {
	.name		= "ykneo",
	.parse_option	= ykn_parse_option,
	.check_atr_hb	= ykn_check_atr_hb,
	.prologue	= ykn_prologue,
	.trancieve	= ykn_trancieve,
	.epilogue	= ykn_epilogue,
};
