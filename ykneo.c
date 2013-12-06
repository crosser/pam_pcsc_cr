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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

#include "token.h"

#define NAMEPFX "YubikeyNEO"

static const BYTE selcmd[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0,
				0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x00};
static const BYTE yk_cmd[] = {0x00, 0x01, 0xff, 0x00};

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

static DWORD ykn_getserial(SCARDHANDLE hCard, BYTE *recv, LPDWORD recvsize_p)
{
	DWORD rc;
	BYTE rbuf[4 + 2];
	DWORD rsize = sizeof(rbuf);
	BYTE sbuf[sizeof(yk_cmd) + 1];
	unsigned int serial;

	memcpy(sbuf, yk_cmd, sizeof(yk_cmd));
	sbuf[2] = 0x10; /* read serial */
	sbuf[4] = rsize;
	rc = SCardTransmit(hCard, &pioSendPci, sbuf, sizeof(sbuf),
			NULL, rbuf, &rsize);
	if (rc) return rc;
	if ((rbuf[rsize-2] != 0x90) || (rbuf[rsize-1] != 0x00))
		return SCARD_W_CARD_NOT_AUTHENTICATED;
	serial = (rbuf[0]<<24) + (rbuf[1]<<16) + (rbuf[2]<<8) + (rbuf[3]);
	rc = snprintf((char*)recv, *recvsize_p, "%u", serial);
	*recvsize_p = rc;
	return SCARD_S_SUCCESS;
}

static DWORD ykn_trancieve(SCARDHANDLE hCard,
	BYTE *send, DWORD sendsize, BYTE *recv, LPDWORD recvsize_p)
{
	DWORD rc;
	DWORD rsize = *recvsize_p + 2;
	BYTE *rbuf = alloca(rsize);
	BYTE *sbuf = alloca(sendsize + 6);
	memcpy(sbuf, yk_cmd, sizeof(yk_cmd));
	sbuf[2] = cr_for_slot[slot];
	sbuf[sizeof(yk_cmd)] = sendsize;
	memcpy(sbuf + sizeof(yk_cmd) + 1, send, sendsize);
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
	.getserial	= ykn_getserial,
	.trancieve	= ykn_trancieve,
	.epilogue	= ykn_epilogue,
};
