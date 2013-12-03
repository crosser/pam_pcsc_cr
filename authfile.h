#ifndef _AUTHFILE_H
#define _AUTHFILE_H

void authfile_template(char *template);

struct _auth_obj authfile(const char *tokenid,
		const char *userid, const char *password,
		void (*update_nonce)(char *nonce, const int nonsize),
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize));

#endif
