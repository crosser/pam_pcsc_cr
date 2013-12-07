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
#ifdef HAVE_SECURITY_PAM_EXT_H
# include <security/pam_ext.h>
#endif

#ifndef PAM_EXTERN
# ifdef PAM_STATIC
#  define PAM_EXTERN static
# else
#  define PAM_EXTERN extern
# endif
#endif

struct _cfg {
	int noaskpass;
	int verbose;
	int injectauth;
};

#ifndef HAVE_PAM_GET_AUTHTOK
static int pam_get_authtok(pam_handle_t *pamh, int item, const char **authtok,
			const char *prompt)
{
	struct _cfg dfl_cfg = {0};
	struct _cfg *cfg = &dfl_cfg;
	struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;
	int pam_err;

	(void)pam_get_data(pamh, "pcsc_cr_cfg_struct", (const void **)&cfg);

	if ((pam_err = pam_get_item(pamh, PAM_AUTHTOK,
					(const void **)authtok))) {
		if (cfg->verbose) syslog(LOG_ERR,
					"get_item(PAM_AUTHTOK) failed: %s",
					pam_strerror(pamh, pam_err));
	} else {
		if (*authtok) return PAM_SUCCESS;
	}

	if ((pam_err = pam_get_item(pamh, PAM_CONV,
				(const void **)&conv))) {
		if (cfg->verbose) syslog(LOG_ERR,
				"get_item(PAM_CONV) failed: %s",
				pam_strerror(pamh, pam_err));
		return pam_err;
	}
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = prompt;
	msgp = &msg;
	resp = NULL;
	pam_err =  (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
	if (resp != NULL) {
		if (pam_err == PAM_SUCCESS) *authtok = resp->resp;
		else free(resp->resp);
		free(resp);
	}
	return pam_err;
}
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

void parse_cfg(struct _cfg * const cfg, int argc, const char *argv[])
{
	int i;

	for (i = 0; i < argc; i++) {
		if (strchr(argv[i],':') && strchr(argv[i],'=')) {
			if (pcsc_option(argv[i]))
				syslog(LOG_ERR,
				"unrecognized pcsc backedn option \"%s\"",
						argv[i]);
		} else if (!strcmp(argv[i], "verbose")) cfg->verbose = 1;
		else if (!strcmp(argv[i], "noaskpass")) cfg->noaskpass = 1;
		else if (!strcmp(argv[i], "injectauth")) cfg->injectauth = 1;
		else if (!strncmp(argv[i], "path=", 5))
					authfile_template(argv[i]+5);
		else syslog(LOG_ERR, "unrecognized arg: \"%s\"", argv[i]);

		if (cfg->verbose) syslog(LOG_DEBUG, "arg: \"%s\"", argv[i]);
	}
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
	int argc, const char *argv[])
{
	struct _cfg cfg = {0};
	const char *tokenid = NULL;
	const char *user;
	const char *password;
	struct _auth_obj ao;
	int pam_err;

	parse_cfg(&cfg, argc, argv);
	(void)pam_set_data(pamh, "pcsc_cr_cfg_struct", &cfg, NULL);

	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		if (cfg.verbose) syslog(LOG_ERR, "get_user failed: %s",
					pam_strerror(pamh, pam_err));
		return pam_err;
	}
	if (strspn(user, "0123456789") == strlen(user)) {
		tokenid = user;
		user = NULL;
	}
	if (cfg.verbose) syslog(LOG_DEBUG, "tokenid=\"%s\", user=\"%s\"",
				tokenid?tokenid:"<none>", user?user:"<none>");

	if (!cfg.noaskpass) {
		if ((pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
					(const char **)&password,
					"Token password:"))) {
			if (cfg.verbose) syslog(LOG_ERR,
						"get_authtok failed: %s",
						pam_strerror(pamh, pam_err));
			return pam_err;
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
		if (cfg.injectauth && ao.payload && ao.payload[0])
			pam_set_item(pamh, PAM_AUTHTOK, ao.payload);
		if (cfg.verbose) syslog(LOG_DEBUG, "authenticated");
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
PAM_MODULE_ENTRY("pam_pcsc_cr");
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
