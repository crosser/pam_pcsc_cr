# $Id: Makefile.am 295 2005-05-13 14:58:27Z crosser $
                                                                                
AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

noinst_HEADERS = pcsc_cr.h token.h

EXTRA_LTLIBRARIES = libpcsc_cr.la
libpcsc_cr_la_SOURCES = crypto.c pcsc_cr.c ykneo.c
EXTRA_libpcsc_cr_la_SOURCES = ossl_crypto.c tom_prypto.c
libpcsc_cr_la_LIBADD = @CRYPTO_OBJS@
libpcsc_cr_la_DEPENDENCIES = @CRYPTO_OBJS@

lib_LTLIBRARIES = pam_pcsc_cr.la
pam_pcsc_cr_la_LDFLAGS = -module -avoid-version
pam_pcsc_cr_la_LIBADD = libpcsc_cr.la

check_PROGRAMS = test_cr
test_cr_LDADD = libpcsc_cr.la

EXTRA_DIST = autogen.sh

TESTS = test_cr
