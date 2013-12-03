#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <alloca.h>
#include "authobj.h"
#include "authfile.h"

/*
 * Template string may contain zero or one '~' and zero or one '?'.
 * '~' at the beginning of the template string is substituted with
 * the home directory of the userid. In any other position it is
 * substituted with the userid itself. '?' is substituted with the
 * tokenid. There is no way to make the resulting path contain '~'
 * or '?'. If there is more than one '~' or '?', or if the '~' is
 * at the beginning but userid does not resolve via getpwnam, or
 * the character to substitute is present but the argument is NULL,
 * NULL is returned. Otherwise, malloc()'ed area containg the path
 * string.
 */

static char *template = "~/.pam_cr/auth";

void authfile_template(char *str)
{
	template = str;
}

static int path_size(const char *tokenid, const char *userid)
{
	const char *usub;
	char *p, *q;
	struct passwd *pw;

	if ((p = strchr(template, '~')) != strrchr(template, '~')) return 0;
	if ((q = strchr(template, '?')) != strrchr(template, '?')) return 0;
	if (p && !userid) return 0;
	if (q && !tokenid) return 0;
	if (p == template) {
		pw = getpwnam(userid);
		if (!pw) return 0;
		usub = pw->pw_dir;
	} else {
		usub = userid;
	}
	return strlen(template) + p?strlen(usub):0 + q?strlen(tokenid):0 + 1;
}

static void
make_path(char * const path, const char *tokenid, const char *userid)
{
	const char *usub;
	char *p, *q;
	struct passwd *pw;

	path[0] = '\0';
	if (template[0] == '~') {
		pw = getpwnam(userid);
		if (!pw) return;
		usub = pw->pw_dir;
	} else {
		usub = userid;
	}
	q = path;
	for (p = template; *p; p++) switch (*p) {
	case '~':
		strcpy(q, usub);
		while (*q) q++;
		break;
	case '?':
		strcpy(q, tokenid);
		while (*q) q++;
		break;
	default:
		*q++ = *p;
		break;
	}
	*q = '\0';
}

struct _auth_obj authfile(const char *tokenid,
		const char *userid, const char *password,
		void (*update_nonce)(char *nonce, const int nonsize),
		const unsigned char *secret, const int secsize,
		const unsigned char *payload, const int paylsize,
		struct _auth_chunk (*fetch_key)(const unsigned char *chal,
						const int csize))
{
	struct _auth_obj ret = {0};
	mode_t oldmask;
	FILE *fp = NULL;
	char *fn;
	int fnl;
	char *buf = NULL;
	const char *wtokenid = "", *wuserid = NULL, *wnonce = NULL;
	const char *hablob = NULL;
	unsigned char *ablob = NULL;
	int blobsize = 0;
	char *newnonce;
	int nonsize;
	struct _auth_obj ao;

	if ((fnl = path_size(tokenid, userid)) == 0) {
		ret.err = "authfile path impossible to build";
		return ret;
	}
	fn = alloca(fnl);
	make_path(fn, tokenid, userid);
	fp = fopen(fn, "r");
	if (fp) {
		struct stat st;
		int fd = fileno(fp);

		if (fstat(fd, &st)) st.st_size = 2047;
		if (st.st_size > 2047) st.st_size = 2047;
		buf = alloca(st.st_size + 1);
		if (fgets(buf, st.st_size + 1, fp)) {
			char *p;

			p = &buf[strlen(buf) - 1];
			while (*p == '\n' || *p == '\r') *p-- = '\0';
			wtokenid = strtok(buf, ":");
			wuserid = strtok(NULL, ":");
			wnonce = strtok(NULL, ":");
			hablob = strtok(NULL, ":");
		} else {
			ret.err = strerror(errno);
		}
		fclose(fp);
	}
	if (ret.err) return ret;

	if (hablob) {
		int hlen = strlen(hablob);
		if (hlen % 32 != 0) {
			ret.err = "error: auth string has wrong length";
		} else if (hlen !=
				strspn(hablob, "0123456789abcdefABCDEF")) {
			ret.err = "error: auth string not hexadecimal";
		} else {
			int i;

			blobsize = hlen/2;
			ablob = alloca(blobsize);
			for (i = 0; i < blobsize; i++)
				sscanf(&hablob[i*2], "%2hhx", &ablob[i]);
		}
	}
	if (ret.err) return ret;

	nonsize = wnonce ? strlen(wnonce)*2 : 32;
	if (nonsize < 32) nonsize = 32;
	newnonce = alloca(nonsize);
	if (wnonce) strcpy(newnonce, wnonce);
	else memset(newnonce, 0, nonsize);
	update_nonce(newnonce, nonsize);

	ao = authobj(userid?userid:wuserid, password,
			wnonce, newnonce, secret, secsize,
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
	if ((fp = fopen(fn, "w"))) {
		int i;

		if (fprintf(fp, "%s:%s:%s:", tokenid?tokenid:wtokenid,
				userid?userid:wuserid, newnonce) < 0) {
			ret.err = strerror(errno);
		} else for (i = 0; i < ao.datasize; i++)
		    if (fprintf(fp, "%02x", ao.data[i]) < 0) {
			ret.err = strerror(errno);
		}
		fprintf(fp, "\n");
		if (fclose(fp) < 0) {
			ret.err = strerror(errno);
		}
	} else {
		ret.err = strerror(errno);
	}
	(void)umask(oldmask);

	if (!ret.err) {
		int bufsize = (wuserid?strlen(wuserid)+1:0) + ao.paylsize;
		if (bufsize) {
			if ((ret.buffer = malloc(bufsize)) == NULL) {
				ret.err = "authfile malloc failed";
			} else {
				unsigned char *p = ret.buffer;
				if (wuserid) {
					strcpy((char*)p, wuserid);
					ret.data = p;
					ret.datasize = strlen(wuserid)+1;
					p += strlen(wuserid)+1;
				}
				if (ao.payload) {
					memcpy(p, ao.payload, ao.paylsize);
					ret.payload = p;
					ret.paylsize = ao.paylsize;
				}
			}
		}
	}

	if (ao.data) memset(ao.data, 0, ao.datasize);
	if (ao.payload) memset(ao.payload, 0, ao.paylsize);
	if (ao.buffer) free(ao.buffer);
	return ret;
}
