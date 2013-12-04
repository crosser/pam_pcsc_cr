#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include "authobj.h"
#include "authfile.h"
#include "pcsc_cr.h"

#ifndef PIC
# define PAM_STATIC
#endif

#define PAM_SM_AUTH

#ifdef HAVE_SECURITY_PAM_APPL_H
# include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
# include <security/pam_modules.h>
#endif

#ifndef PAM_EXTERN
# ifdef PAM_STATIC
#  define PAM_EXTERN static
# else
#  define PAM_EXTERN extern
# endif
#endif

static struct _auth_chunk
token_key(const unsigned char *challenge, const int challengesize)
{
	struct _auth_chunk ho = {0};
	long rc;
	int keysize = sizeof(ho.data);

	if ((rc = pcsc_cr(challenge, challengesize, ho.data, &keysize))) {
		ho.err = pcsc_errstr(rc);
	}
	return ho;
}

static void update_nonce(char *nonce, const int nonsize)
{
	int n = 0;

	sscanf(nonce, "%d", &n);
	snprintf(nonce, nonsize, "%d", n+1);
}

struct _cfg {
	int verbose;
};

void parse_cfg(struct _cfg * const cfg, int argc, const char *argv[])
{
	int i;

	for (i = 0; i < argc; i++) {
		if (strchr(argv[i],':') && strchr(argv[i],'='))
			pcsc_option(argv[i]);
		else if (!strcmp(argv[i], "verbose")) cfg->verbose = 1;
	}
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct _cfg cfg;
	const char *tokenid = NULL;
	const char *user;
	const char *password;
	struct _auth_obj ao;
	int pam_err;

	parse_cfg(&cfg, argc, argv);

	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		if (cfg.verbose) syslog(LOG_ERR, "get_user failed: %s",
					pam_strerror(pamh, pam_err));
		return (pam_err);
	}
	if (strspn(user, "0123456789") == strlen(user)) {
		tokenid = user;
		user = NULL;
	}

	if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
		if ((pam_err = pam_get_item(pamh, PAM_AUTHTOK,
					(const void **)&password))) {
			if (cfg.verbose) syslog(LOG_ERR,
					"get_authtok failed: %s",
					pam_strerror(pamh, pam_err));
			return (pam_err);
		}
	} else {
		password = "";
	}

	ao = authfile(tokenid, user, password, update_nonce,
			NULL, 0, NULL, 0, token_key);
	if (ao.err) {
		if (cfg.verbose) syslog(LOG_INFO, "authfile: %s", ao.err);
		return PAM_AUTH_ERR;
	} else {
		if (!user)
			pam_set_item(pamh, PAM_USER, ao.data);
		if (ao.payload && ao.payload[0])
			pam_set_item(pamh, PAM_AUTHTOK, ao.payload);
		return PAM_SUCCESS;
	}
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	return PAM_SERVICE_ERR;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_unix");
#endif

#ifdef PAM_STATIC
struct pam_module _pam_pcsc_cr_modstruct = {
	"pam_pcsc_cr",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};
#endif
