#ifndef _AUTHOBJ_H
#define _AUTHOBJ_H

struct _auth_obj {
	unsigned char *buffer;	/* to be free()'d if not NULL */
	const char *err;	/* non-NULL if failed */
	unsigned char *authobj;
	int authsize;
	unsigned char *payload;
	int paylsize;
};

/* Construct new authobj from the given secret and other data */
struct _auth_obj new_authobj(const char *userid, const char *password,
				const char *nonce,
			const unsigned char *secret, const int secsize,
			const unsigned char *payload, const int paysize);

/* Unwrap old authobj, extract payload, construct new one with newnonce */
struct _auth_obj verify_authobj(const char *userid, const char *password,
				const char *oldnonce, const char *newnonce,
			const unsigned char *authobj, const int authsize);

/* Unwrap old authobj, replace the payload, construct new one with newnonce */
struct _auth_obj reload_authobj(const char *userid, const char *password,
				const char *oldnonce, const char *newnonce,
			const unsigned char *authobj, const int authsize,
			const unsigned char *payload, const int paysize);

#endif
