dnl Process this file with autoconf to produce a configure script.

AC_INIT([pam_pcsc_cr], 0.0.1)
AC_CONFIG_SRCDIR([pam_pcsc_cr.c])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
AM_CONFIG_HEADER([config.h])
AC_LANG_C
AC_PROG_CC

if test "X$CC" = "Xgcc"; then
  CFLAGS="$CFLAGS -Wall -g"
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

AC_SUBST(PCSC_LIBS)
AC_SUBST(PCSC_CFLAGS)
CFLAGS="$PCSC_CFLAGS $CFLAGS"
LIBS="$PCSC_LIBS $LIBS"

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
