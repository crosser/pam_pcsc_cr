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
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <alloca.h>
#include "base64.h"
#include "authobj.h"
#include "authfile.h"

/*
 * Template string may contain zero or one '~' and zero or one '?'.
 * '~' at the beginning of the template string is substituted with
 * the home directory of the userid. In any other position it is
 * substituted with the userid itself. There is no way to make the
 * resulting path contain '~'. If there is more than one '~', or if
 * the '~' is at the beginning but userid does not resolve via
 * getpwnam, or '~' is present but the argument is NULL, path_size
 * returns 0, and make_path returns 1.
 */

static const char *template = "~/.pam_cr/auth";

void authfile_template(const char *str)
{
	template = str;
}

/*
  I know using these two functions and alloca() in between it ugly, but
  I like the alternatives even less. =ec
*/

static int path_size(const struct passwd *pw)
{
	const char *p;

	if ((p = strchr(template, '~')) != strrchr(template, '~')) return 0;
	if (p && !pw) return 0;
	if (p == template) return strlen(template)+strlen(pw->pw_dir)+1;
	else return strlen(template)+strlen(pw->pw_name)+1;
}

static int
make_path(char * const path, const struct passwd *pw)
{
	const char *p;
	char *q;

	path[0] = '\0';
	q = path;
	for (p = template; *p; p++) switch (*p) {
	case '~':
		if (!pw) return 1;
		if (p == template) strcpy(q, pw->pw_dir);
		else strcpy(q, pw->pw_name);
		while (*q) q++;
		break;
	default:
		*q++ = *p;
		break;
	}
	*q = '\0';
	return 0;
}

int parse(char * const buf, const int argc, const char *argv[const])
{
	char *p, *q;
	int i;

	for (i = 0, p = buf; *p; p = q+1, i++) {
		for (q = p; *q && *q != ':' && *q != '\r' && *q != '\n'; q++) ;
		*q = '\0';
		if (*p && i < argc) argv[i] = p;
	}
	return i != argc;
}

struct _auth_obj authfile(const char *userid, const char *password,
		void (*update_nonce)(char *nonce, const int nonsize),
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paylsize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize))
{
	struct _auth_obj ret = {0};
	const struct passwd *pw = NULL;
	mode_t oldmask;
	FILE *fp = NULL;
	char *fn, *nfn;
	int fnl;
	struct stat st = {0};
	char *buf = NULL;
	struct {
		const char *userid;
		const char *nonce;
		const char *hablob;
	} w = {NULL, NULL, NULL};
	unsigned char *ablob = NULL;
	int blobsize = 0;
	char *newnonce;
	int nonsize;
	struct _auth_obj ao;

	if (userid) pw = getpwnam(userid);
	if ((fnl = path_size(pw)) == 0) {
		ret.err = "authfile path_size failed";
		return ret;
	}
	fn = alloca(fnl);
	if (make_path(fn, pw)) {
		ret.err = "authfile make_path failed";
		return ret;
	}
	nfn = alloca(fnl+32);
	snprintf(nfn, fnl+32, "%s.%d.%ld", fn, (int)getpid(), (long)time(NULL));
	fp = fopen(fn, "r");
	if (fp) {
		if (fstat(fileno(fp), &st)) st.st_size = 2047;
		if (st.st_size > 2047) st.st_size = 2047;
		buf = alloca(st.st_size + 1);
		if (!fgets(buf, st.st_size + 1, fp)) {
			ret.err = strerror(errno);
		} else if (parse(buf, sizeof(w)/sizeof(char*),
					(const char ** const)&w)){
			ret.err = "error: unparseable auth file";
		}
		fclose(fp);
	}
	if (ret.err) return ret;

	if (w.hablob) {
		blobsize = strlen(w.hablob)*3/4;
		ablob = alloca(blobsize);
		if (b64_decode(w.hablob, ablob, &blobsize))
			ret.err = "error: undecodeable auth string";
	}
	if (ret.err) return ret;

	nonsize = w.nonce ? strlen(w.nonce)*2 : 32;
	if (nonsize < 32) nonsize = 32;
	newnonce = alloca(nonsize);
	if (w.nonce) strcpy(newnonce, w.nonce);
	else memset(newnonce, 0, nonsize);
	update_nonce(newnonce, nonsize);

	ao = authobj(userid?userid:w.userid, password,
			w.nonce, newnonce, secret, secsize,
			payload, paylsize, ablob, blobsize,
			fetch_key);

	if (ao.err) {
		ret.err = ao.err;
		if (ao.data) memset(ao.data, 0, ao.datasize);
		if (ao.payload) memset(ao.payload, 0, ao.paylsize);
		if (ao.buffer) free(ao.buffer);
		return ret;
	}

	oldmask = umask(077);
	if ((fp = fopen(nfn, "w"))) {
		int bsize = ((ao.datasize-1)/3+1)*4+1;
		char *b64 = alloca(bsize);

		if (b64_encode(ao.data, ao.datasize, b64, &bsize)) {
			ret.err = "error: could not encode auth string";
		} else if (fprintf(fp, "%s:%s:%s\n",
				userid?userid:w.userid, newnonce, b64) < 0) {
			ret.err = strerror(errno);
		}
		if (st.st_uid || st.st_gid) {
			if (fchown(fileno(fp), st.st_uid, st.st_gid)) /*ign*/;
		}
		if (fclose(fp) < 0) {
			ret.err = strerror(errno);
		}
	} else {
		ret.err = strerror(errno);
	}
	(void)umask(oldmask);
	if (ret.err) {
		unlink(nfn); /* may not exist but no matter */
	} else if (rename(nfn, fn)) {
		ret.err = strerror(errno);
	}

	if (!ret.err) {
		int bufsize = (w.userid?strlen(w.userid)+1:0) + ao.paylsize + 1;
		if (bufsize) {
			if ((ret.buffer = malloc(bufsize)) == NULL) {
				ret.err = "authfile malloc failed";
			} else {
				unsigned char *p = ret.buffer;
				if (w.userid) {
					strcpy((char*)p, w.userid);
					ret.data = p;
					ret.datasize = strlen(w.userid)+1;
					p += strlen(w.userid)+1;
				}
				if (ao.payload) {
					memcpy(p, ao.payload, ao.paylsize);
					p[ao.paylsize] = '\0';
					ret.payload = p;
					ret.paylsize = ao.paylsize+1;
				}
			}
		}
	}

	if (ao.data) memset(ao.data, 0, ao.datasize);
	if (ao.payload) memset(ao.payload, 0, ao.paylsize);
	if (ao.buffer) free(ao.buffer);
	return ret;
}
