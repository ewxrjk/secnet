dnl -*-autoconf-*-
dnl subdirmk example - configuration script
dnl  Copyright 2019 Mark Wooding
dnl  Copyright 2019 Ian Jackson
dnl SPDX-License-Identifier: LGPL-2.0-or-later

AC_INIT([mktoy], [0.9.0], [mdw@distorted.org.uk])
AC_CONFIG_SRCDIR([src/toy.c])
AC_CONFIG_AUX_DIR([build-aux])

AC_PROG_INSTALL

AC_PROG_CC
INCLUDES=
AC_SUBST(INCLUDES)

m4_include([subdirmk/subdirmk.ac])

SUBDIRMK_SUBDIRS([lib])
SUBDIRMK_SUBDIRS([lib/t src])

AC_OUTPUT

dnl----- That's all, folks --------------------------------------------------
