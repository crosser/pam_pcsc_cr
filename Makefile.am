# $Id: Makefile.am 295 2005-05-13 14:58:27Z crosser $
                                                                                
AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

libdir = $(PAMDIR)
DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@

noinst_HEADERS = pcsc_cr.h token.h crypto_if.h crypto.h serial.h authobj.h \
		authfile.h

EXTRA_LTLIBRARIES = libpcsc_cr.la
libpcsc_cr_la_SOURCES = authfile.c authobj.c serial.c crypto.c pcsc_cr.c \
			ykneo.c
EXTRA_libpcsc_cr_la_SOURCES = ossl_crypto.c tom_crypto.c gnu_crypto.c
libpcsc_cr_la_LIBADD = @CRYPTO_OBJS@
libpcsc_cr_la_DEPENDENCIES = @CRYPTO_OBJS@

lib_LTLIBRARIES = pam_pcsc_cr.la
pam_pcsc_cr_la_LDFLAGS = -module -avoid-version
pam_pcsc_cr_la_LIBADD = libpcsc_cr.la

bin_PROGRAMS = pam_cr_setup
pam_cr_setup_LDADD = libpcsc_cr.la

check_PROGRAMS = test_auth test_serial test_crypto test_chalresp
test_auth_LDADD = libpcsc_cr.la
test_serial_LDADD = libpcsc_cr.la
test_crypto_LDADD = libpcsc_cr.la
test_chalresp_LDADD = libpcsc_cr.la

EXTRA_DIST = autogen.sh README_CR

TESTS = test_auth test_serial test_crypto test_chalresp
XFAIL_TESTS = test_chalresp
