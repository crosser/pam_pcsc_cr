#ifndef _AUTHOBJ_H
#define _AUTHOBJ_H

int make_authobj(const char *id, const char *pass, const char *nonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize,
		unsigned char *buffer, int *bufsize);
int parse_authobj(const unsigned char *hmacdata, const int hmacdatasize,
		const unsigned char *buffer, const int bufsize,
		unsigned char *secret, int *secsize,
		unsigned char *payload, int *paysize);

#endif
