#ifndef _AUTHOBJ_H
#define _AUTHOBJ_H

#define AUTHCHUNKSIZE 20

struct _auth_chunk {
	const char *err;
	unsigned char data[AUTHCHUNKSIZE];
};

struct _auth_obj {
	unsigned char *buffer;	/* to be free()'d if not NULL */
	const char *err;	/* non-NULL if failed */
	unsigned char *data;
	int datasize;
	unsigned char *payload;
	int paylsize;
};

/* Construct new or repack old authobj, return payload */
struct _auth_obj authobj(const char *userid, const char *password,
		const char *oldnonce, const char *newnonce,
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paysize,
		const unsigned char *ablob, const int blobsize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize));

#endif
