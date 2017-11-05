dnl Process this file with autoconf to produce a configure script.

AC_INIT([pam_pcsc_cr], 0.9.4)
AC_CONFIG_SRCDIR([pam_pcsc_cr.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])
AC_LANG_C
AC_PROG_CC

if test "X$CC" = "Xgcc"; then
  CFLAGS="$CFLAGS -Wall"
fi

AC_PROG_MAKE_SET
AC_SUBST(PROGS)dnl
AC_SUBST(LIBPROGS)dnl
AC_PROG_INSTALL
AM_PROG_LIBTOOL
PKG_PROG_PKG_CONFIG

AC_CHECK_HEADERS([security/pam_appl.h], [], [
  AC_MSG_ERROR([[PAM headers not found]])
])
AC_CHECK_HEADERS([security/pam_modules.h security/pam_ext.h], [], [], [
#include <sys/types.h>
#include <security/pam_appl.h>
])
AC_CHECK_LIB([pam], [pam_start])
AC_CHECK_FUNCS([pam_get_authtok])
pamdir=/lib/${host_cpu}-${host_os}/security
AC_ARG_WITH(pam-dir,
	[  --with-pam-dir=DIR      path to install the PAM module (${pamdir})],
	[PAMDIR="$withval"],
	[
case $prefix in
*/_inst) PAMDIR="${prefix}${pamdir}" ;;
*)       PAMDIR=${pamdir} ;;
esac
])
AC_SUBST(PAMDIR)
AC_MSG_NOTICE([Installation target PAMDIR=${PAMDIR}])

PKG_CHECK_MODULES([PCSC], [libpcsclite])
CPPFLAGS="$PCSC_CFLAGS $CPPFLAGS"
LIBS="$PCSC_LIBS $LIBS"

PKG_CHECK_MODULES([OPENSSL], [libcrypto], [], [:])
AS_IF([test "x$OPENSSL_CFLAGS" != "x" -o "x$OPENSSL_LIBS" != "x" ], [
  use_openssl=yes
])
CPPFLAGS="$OPENSSL_CFLAGS $CPPFLAGS"
LIBS="$OPENSSL_LIBS $LIBS"

AC_ARG_ENABLE(tomcrypt,
	[  --enable-tomcrypt       use libtomcrypt even when openssl is present])

AS_IF([test "x$use_openssl" != "xyes" -o "x$enable_tomcrypt" = "xyes"], [
  PKG_CHECK_MODULES([TOMCRYPT], [libtomcrypt], [], [:])
])
AS_IF([test "x$TOMCRYPT_CFLAGS" != "x" -o "x$TOMCRYPT_LIBS" != "x" ], [
  use_tomcrypt=yes
])
CPPFLAGS="$TOMCRYPT_CFLAGS $CPPFLAGS"
LIBS="$TOMCRYPT_LIBS $LIBS"

AC_ARG_ENABLE(gcrypt,
	[  --enable-gcrypt         use libgcrypt even when openssl or libtomcrypt
                          is present])

AS_IF([test "x$use_openssl" != "xyes" && test "x$use_tomcrypt" != "xyes" || \
	test "x$enable_tomcrypt" = "xyes"], [
  AM_PATH_LIBGCRYPT()
])
AS_IF([test "x$LIBGCRYPT_CFLAGS" != "x" -o "x$LIBGCRYPT_LIBS" != "x" ], [
  use_gcrypt=yes
])
CPPFLAGS="$LIBGCRYPT_CFLAGS $CPPFLAGS"
LIBS="$LIBGCRYPT_LIBS $LIBS"

AS_IF([test "x$use_openssl" != "xyes" -a "x$use_tomcrypt" != "xyes" -a "x$use_gcrypt" != "xyes"], [
  AC_MSG_ERROR([[Neither openssl, tomcrypt or gcrypt libraries present]])
])

AS_IF([test "x$use_openssl" = "xyes"], [
  CRYPTO_OBJS+=" ossl_crypto.lo"
  AC_DEFINE([HAVE_OPENSSL], [1], [Use openssl libcrypto])
])
AS_IF([test "x$use_tomcrypt" = "xyes"], [
  CRYPTO_OBJS+=" tom_crypto.lo"
  AC_DEFINE([HAVE_TOMCRYPT], [1], [Use libtomcrypt])
])
AS_IF([test "x$use_gcrypt" = "xyes"], [
  CRYPTO_OBJS+=" gnu_crypto.lo"
  AC_DEFINE([HAVE_GCRYPT], [1], [Use libgcrypt])
])
AC_SUBST(CRYPTO_OBJS)

dnl Checks for header files.
AC_HEADER_STDC
AC_HEADER_TIME

AC_CHECK_HEADERS([winscard.h reader.h], [],
  [AC_MSG_ERROR([[pcsclite headers not found]])])
AC_CHECK_LIB([pcsclite], [SCardEstablishContext], [],
  [AC_MSG_ERROR([[pcsclite library not useable]])])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
