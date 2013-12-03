#ifndef _PCSC_CR_H
#define _PCSC_CR_H

int pcsc_option(const char *option);
long pcsc_cr(const unsigned char *chal, const int csize,
		unsigned char *resp, int *rsize);
char *pcsc_errstr(long err);

#endif
