# $Id: Makefile.am 295 2005-05-13 14:58:27Z crosser $
                                                                                
AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

LIBS = @LIBS@
pamlibdir = @pamlibdir@

noinst_HEADERS = pcsc_cr.h token.h

lib_LTLIBRARIES = pam_pcsc_cr.la
EXTRA_pam_pcsc_cr_la_SOURCES = ossl_crypto.c tom_prypto.c
pam_pcsc_cr_la_SOURCES = crypto.c pcsc_cr.c ykneo.c
pam_pcsc_cr_la_LDFLAGS = -module -avoid-version
pam_pcsc_cr_la_LIBADD = @CRYPTO_OBJS@
pam_pcsc_cr_la_DEPENDENCIES = @CRYPTO_OBJS@

EXTRA_DIST = autogen.sh

TESTS = test_cr

CLEANFILES = test_cr
