dnl -*-autoconf-*-
dnl
dnl Configuration script for toy project
dnl
dnl (c) 2019 Mark Wooding
dnl

dnl----- Licensing notice ---------------------------------------------------
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU Library General Public License as
dnl published by the Free Software Foundation; either version 2 of the
dnl License, or (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU Library General Public License for more details.
dnl
dnl You should have received a copy of the GNU Library General Public
dnl License along with this program; if not, write to the Free
dnl Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
dnl MA 02111-1307, USA.

AC_INIT([mktoy], [0.9.0], [mdw@distorted.org.uk])
AC_CONFIG_SRCDIR([src/toy.c])
AC_CONFIG_AUX_DIR([build-aux])

AC_PROG_INSTALL

AC_PROG_CC
INCLUDES=
AC_SUBST(INCLUDES)

m4_define([SUBDIRSMK_SUBDIRS],
[m4_map_args_w([$1],[_SUBDIRSMK_SUBDIR(],[/)])])dnl

AC_CONFIG_FILES([subdirs.mk:subdirs.mk.tmp Subdir.mk:Subdir.mk.tmp],[],
[echo 'running subdirmk-setup'
'$srcdir'/build-aux/subdirmk-setup --srcdir '$srcdir' $subdirsmk_subdirs])

m4_define([_SUBDIRSMK_SUBDIR],
[subdirsmk_subdirs="$subdirsmk_subdirs '$1'"
AC_CONFIG_FILES([$1Subdir.mk:$1Subdir.mk.tmp])])dnl

SUBDIRSMK_SUBDIRS([lib lib/t src])

AC_OUTPUT

dnl----- That's all, folks --------------------------------------------------
