# aclocal.m4 - package-specific macros for autoconf

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

dnl This next macro came from adns.git,
dnl (d8fa191ed7774818862febd6ade774cb7e149ab9).
define(ADNS_C_GETFUNC,[
 AC_CHECK_FUNC([$1],,[
  AC_CHECK_LIB([$2],[$1],[$3],[
    AC_MSG_ERROR([cannot find library function $1])
  ])
 ])
])

define(SECNET_C_GETFUNC,[
 ADNS_C_GETFUNC($1,$2,[
  LIBS="-l$2 $LIBS";
  AC_MSG_WARN([$1 is in lib$2, urgh.  Must use -l$2.])
 ])
])
