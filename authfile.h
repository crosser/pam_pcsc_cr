#ifndef _AUTHFILE_H
#define _AUTHFILE_H

int eprint(const char *format, ...);	/* must be provided by the caller */

int update_authfile(const char *fn, const char *tokenid, const char *id,
		const char *password, const char *nonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize);

#endif
