#ifndef _PCSC_CR_H
#define _PCSC_CR_H

long pcsc_cr(unsigned char *chal, int csize, unsigned char *resp, int *rsize);
char *pcsc_errstr(long err);

#endif
