#include <stdio.h>
#include <string.h>
#include <alloca.h>
#include "token.h"
#include <reader.h>

extern struct token_interface ykneo_interface;

static struct token_interface *types[] = {
	&ykneo_interface,
	NULL,
};

SCARD_IO_REQUEST pioSendPci;

static LONG find_hb(BYTE *atr, DWORD atrsize, BYTE **hb, LPDWORD hbsize)
{
	int i, j, cont;
	if (atrsize < 2) return SCARD_W_UNSUPPORTED_CARD;
	switch (atr[0]) {
	case 0x3B: break;
	case 0x3F: break;
	default: return SCARD_W_UNSUPPORTED_CARD;
	}
	*hbsize = atr[1]&0x0f;
	i=1;
	do {
		cont = atr[i]>>4;
		for (j = 0; j < 4; j++) if (cont & (0x01 << j)) i++;
	} while ((cont & 0x08) && (i < atrsize));
	if ((i + (*hbsize) + 2) != atrsize)
		return SCARD_W_UNSUPPORTED_CARD;
	*hb = atr + i + 1;
	return SCARD_S_SUCCESS;
}

long pcsc_cr(unsigned char *chal, int csize, unsigned char *resp, int *rsize)
{
	struct token_interface *type;
	LONG rc;
	SCARDCONTEXT hContext;
	LPTSTR readers, rdr;
	SCARDHANDLE hCard;
	DWORD nrdrs = SCARD_AUTOALLOCATE, activeproto;
	BYTE atr[33];
	DWORD atrsize;
	BYTE *hb;
	DWORD hbsize;
	DWORD lrsize;
	int i;

	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rc) return rc;
	rc = SCardListReaders(hContext, NULL, (LPTSTR)&readers, &nrdrs);
	if (rc) return rc;
	for (rdr=readers; rdr < readers + nrdrs - 1; rdr += strlen(rdr) + 1) {
		rc = SCardConnect(hContext, rdr, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
			&hCard, &activeproto);
		if (rc) continue;
		switch (activeproto) {
		case SCARD_PROTOCOL_T0:
			pioSendPci = *SCARD_PCI_T0;
			break;
		case SCARD_PROTOCOL_T1:
			pioSendPci = *SCARD_PCI_T1;
			break;
		}
		atrsize = sizeof(atr);
		rc = SCardGetAttrib(hCard, SCARD_ATTR_ATR_STRING,
			atr, &atrsize);
		if (rc) goto disconnect;
		rc = find_hb(atr, atrsize, &hb, &hbsize);
		if (rc) goto disconnect;
		for (i = 0; types[i]; i++) {
			type = types[i];
			rc = type->check_atr_hb(hb, hbsize);
			if (rc == 0) break;
		}
		if (rc) goto disconnect;
		rc = type->prologue(hCard);
		if (rc == 0) break;
	disconnect:
		(void)SCardDisconnect(hCard, SCARD_LEAVE_CARD);
	}
	if (rc) goto free_out;
	lrsize = *rsize;
	rc = type->trancieve(hCard, chal, csize, resp, &lrsize);
	if (rc) goto disc_free_out;
	*rsize = lrsize;
	rc = type->epilogue(hCard);
disc_free_out:
	(void)SCardDisconnect(hCard, SCARD_EJECT_CARD);
free_out:
	(void)SCardFreeMemory(hContext, readers);
	return rc;
}

char *pcsc_errstr(long err) {
	return pcsc_stringify_error(err);
}

int pcsc_option(char *option)
{
	char *name, *key, *val;
	int i, rc = -1;
	struct token_interface *type;

	name=(char *)alloca(strlen(option)+1);
	strcpy(name, option);
	if ((key = strchr(name, ':'))) *(key++) = '\0';
	else return -1;
	if ((val = strchr(key, '='))) *(val++) = '\0';
	else return -1;
	if (*val == '\0') return -1;
	for (i = 0; types[i]; i++) {
		type = types[i];
		if (!strcmp(type->name,name)) {
			rc = type->parse_option(key, val);
			break;
		}
	}
	return rc;
}
