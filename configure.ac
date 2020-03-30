dnl Process this file with autoconf to produce a configure script.

dnl This file is part of secnet.
dnl See README for full list of copyright holders.
dnl
dnl secnet is free software; you can redistribute it and/or modify it
dnl under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 3 of the License, or
dnl (at your option) any later version.
dnl 
dnl secnet is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl General Public License for more details.
dnl 
dnl You should have received a copy of the GNU General Public License
dnl version 3 along with secnet; if not, see
dnl https://www.gnu.org/licenses/gpl.html.

sinclude(ac_prog_cc_no_writeable_strings.m4)

m4_include(subdirmk/subdirmk.ac)

AC_INIT(secnet,0.1.18+,secnet@chiark.greenend.org.uk)
AC_CONFIG_SRCDIR(secnet.c)
AC_CONFIG_HEADER(config.h)

SUBDIRMK_SUBDIRS([test-example mtest stest base91s])

AC_PREREQ(2.50)
AC_REVISION($Id: configure.in,v 1.4 2002/09/09 22:05:02 steve Exp $)

AC_LANG_C

# If fink is on the path then it is assumed we should use it.
AC_PATH_PROG([FINK],[fink])
if test "x$FINK" != x; then
  finkdir=`echo $FINK|sed 's,/[[^/]]*/[[^/]]*$,,'`
  CPPFLAGS="-I$finkdir/include ${CPPFLAGS}"
  LDFLAGS="-L$finkdir/lib ${LDFLAGS}"
fi

# This is quite unpleasant.  It turns out that most header checking
# macros call AC_INCLUDES_DEFAULT.  By default AC_INCLUDES_DEFAULT
# implies AC_HEADER_STDC and a bunch of conditional includes.  But
# these header checks are obsolete as the documentation for
# AC_HEADER_STDC says.  Instead, define AC_INCLUDES_DEFAULT ourselves.
# The list of headers below is the list from `(autoconf) Default
# Includes' (filtered by hand for the modern ones rather than the
# fallbacks).  We must include $1 because AC_INCLUDES_DEFAULT is
# called with an argument giving the check-specific haders.
m4_define([AC_INCLUDES_DEFAULT],[
          # include <sys/types.h>
          # include <sys/stat.h>
          # include <stdlib.h>
          # include <stddef.h>
          # include <string.h>
          # include <inttypes.h>
          # include <stdint.h>
          # include <unistd.h>
$1
])

AC_PROG_MAKE_SET
AC_PROG_CC
AC_PROG_INSTALL
AC_CHECK_HEADERS([net/if.h net/route.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([linux/if_tun.h], [], [], 
[#if HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
])
AC_CHECK_HEADERS([stropts.h sys/sockio.h net/if_tun.h])
AC_C_BIGENDIAN
AC_PROG_CC_NO_WRITEABLE_STRINGS(WRITESTRINGS)

AC_ARG_ENABLE(hacky-parallel,
  [AS_HELP_STRING([--enable-hacky-parallel],
                  [parallelise slow cryptography (default is no)])], [
  case "$enableval" in
  n|0|no) ;;
  y|1|yes) CFLAGS="$CFLAGS -DHACKY_PARALLEL" ;;
  *) ;;
  esac
])

AC_DEFUN([REQUIRE_HEADER],[AC_CHECK_HEADER($1,,[AC_MSG_ERROR($1 not found)])])

dnl the order in which libraries is checked is important
dnl eg. adns on Solaris 2.5.1 depends on -lnsl and -lsocket
AC_CHECK_LIB(gmp,mpz_init_set_str)
AC_CHECK_LIB(gmp2,mpz_init_set_str)
AC_CHECK_LIB(gmp,__gmpz_init_set_str)
REQUIRE_HEADER([gmp.h])
dnl Would love to barf if no gmp was found, but how to test? Requiring the header will do for now.
SECNET_C_GETFUNC(inet_ntoa,nsl)
AC_CHECK_LIB(socket,socket)
SECNET_C_GETFUNC(inet_aton,resolv)
AC_CHECK_LIB(adns,adns_init)
REQUIRE_HEADER([adns.h])

AC_CHECK_FUNCS([fmemopen funopen])

dnl gcc 4.9.2 (jessie) requires -std=gnu11 to cope with for (int i=...
dnl but we do not want to pass that everywhere because we don't want
dnl to nail down the C dialect this way.  Why oh why oh why.
m4_define([for_gcc_std],[
void x(void) { for (int i=0; i<1; i++) { } }
])
AC_CACHE_CHECK([required gcc -std flag],[secnet_cv_gcc_std_flag],[
    secnet_cv_gcc_std_flag=""
    AC_COMPILE_IFELSE([AC_LANG_SOURCE(for_gcc_std)],[],[
        old_cflags="$CFLAGS"
	CFLAGS="$CFLAGS -std=gnu11"
	AC_COMPILE_IFELSE([AC_LANG_SOURCE(for_gcc_std)],[
	    secnet_cv_gcc_std_flag=" -std=gnu11"
	],[
	    AC_MSG_RESULT([failure!])
	    AC_MSG_ERROR([cannot get test program to compile],1)
	])
	CFLAGS="$old_cflags"
    ])
])
CFLAGS="$CFLAGS$secnet_cv_gcc_std_flag"

AC_MSG_NOTICE([Checking requirements for IPv6 support...])
enable_ipv6=true
m4_define(NO_IPV6,[enable_ipv6=false])
AC_CHECK_DECL(AF_INET6,        [],[NO_IPV6],[#include <netinet/in.h>])
AC_CHECK_FUNC(adns_addr2text,  [],[NO_IPV6])
if $enable_ipv6; then
    AC_MSG_NOTICE([Enabling IPv6 support])
    AC_DEFINE(CONFIG_IPV6, 1,
              [Define to 1 to use IPv6 support in system and adns])
else
    AC_MSG_WARN([Disabling IPv6 support])
fi

AC_CHECK_DECL([adns_if_monotonic],[
    AC_DEFINE([USE_MONOTONIC],[1],[Use CLOCK_MONOTONIC and adns_if_monotonic])
],[
: dnl AC_MSG_WARN([Using non-monotonic clock, due to lack of adns_if_monotonic])
],[AC_INCLUDES_DEFAULT
#include <adns.h>
])

SUBDIRMK_MAKEFILES(common.make)

AC_OUTPUT(,
          echo timestamp >config.stamp)

AH_TOP([
#ifndef _CONFIG_H
#define _CONFIG_H
])

AH_BOTTOM([
/* -*- c -*- */

/* These used to be in config.h.bot, but are now in configure.in. */

#ifdef __GNUC__
#define NORETURN(_x) void _x __attribute__ ((noreturn))
#define FORMAT(_a,_b,_c) __attribute__ ((format (_a,_b,_c)))
#else
#define NORETURN(_x) _x
#define FORMAT(_a,_b,_c)
#endif

#endif /* _CONFIG_H */
])
