dnl Process this file with autoconf to produce a configure script.

AC_INIT([pam_pcsc_cr], 0.0.1)
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

PKG_CHECK_MODULES([PCSC], [libpcsclite])
AC_ARG_WITH(pcsclite-include-path,
	[  --with-pcsclite-include-path=PATH path to pcsclite includes],
	[PCSC_CFLAGS="-I $withval"],
	[])
AC_ARG_WITH(pcsclite-lib-path,
	[  --with-pcsclite-lib-path=PATH path to pcsclite libs],
	[PCSC_LIBS="-L $withval -lpcsclite"],
	[])

CPPFLAGS="$PCSC_CFLAGS $CPPFLAGS"
LIBS="$PCSC_LIBS $LIBS"

PKG_CHECK_MODULES([OPENSSL], [libcrypto], [], [:])
AC_ARG_WITH(openssl-include-path,
	[  --with-openssl-include-path=PATH path to openssl includes],
	[OPENSSL_CFLAGS="-I $withval"],
	[])
AC_ARG_WITH(openssl-lib-path,
	[  --with-openssl-lib-path=PATH path to openssl libs],
	[OPENSSL_LIBS="-L $withval -lcrypto"],
	[])
AS_IF([test "x$OPENSSL_CFLAGS" != "x" -o "x$OPENSSL_LIBS" != "x" ], [
  use_openssl=yes
])
CPPFLAGS="$OPENSSL_CFLAGS $CPPFLAGS"
LIBS="$OPENSSL_LIBS $LIBS"

AC_ARG_ENABLE(tomcrypt,
	[  --enable-tomcrypt       use libtomcrypt even when openssl present])

AS_IF([test "x$use_openssl" != "xyes" -o "x$enable_tomcrypt" = "xyes"], [
  PKG_CHECK_MODULES([TOMCRYPT], [libtomcrypt], [], [:])
])
AC_ARG_WITH(libtomcrypt-include-path,
	[  --with-libtomcrypt-include-path=PATH path to libtomcrypt includes],
	[TOMCRYPT_CFLAGS="-I $withval"],
	[])
AC_ARG_WITH(libtomcrypt-lib-path,
	[  --with-libtomcrypt-lib-path=PATH path to libtomcrypt libs],
	[TOMCRYPT_LIBS="-L $withval -ltomcrypt"],
	[])
AS_IF([test "x$TOMCRYPT_CFLAGS" != "x" -o "x$TOMCRYPT_LIBS" != "x" ], [
  use_tomcrypt=yes
])
CPPFLAGS="$TOMCRYPT_CFLAGS $CPPFLAGS"
LIBS="$TOMCRYPT_LIBS $LIBS"

AS_IF([test "x$use_openssl" != "xyes" -a "x$use_tomcrypt" != "xyes"], [
  AC_MSG_ERROR([[Neither openssl nor tomcrypt libraries present]])
])

AS_IF([test "x$use_openssl" = "xyes"], [
  CRYPTO_OBJS+=" ossl_crypto.lo"
  AC_DEFINE([HAVE_OPENSSL], [1], [Use openssl libcrypto])
])
AS_IF([test "x$use_tomcrypt" = "xyes"], [
  CRYPTO_OBJS+=" tom_crypto.lo"
  AC_DEFINE([HAVE_TOMCRYPT], [1], [Use libtomcrypt])
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
