dnl @synopsis AC_PROG_CC_NO_WRITEABLE_STRINGS(substvar [,hard])
dnl
dnl Try to find a compiler option that warns when a stringliteral is
dnl used in a place that could potentially modify the address. This
dnl should warn on giving an stringliteral to a function that asks of
dnl a non-const-modified char-pointer.
dnl
dnl The sanity check is done by looking at string.h which has a set
dnl of strcpy definitions that should be defined with const-modifiers
dnl to not emit a warning in all so many places.
dnl
dnl Currently this macro knows about GCC.
dnl hopefully will evolve to use:    Solaris C compiler,
dnl Digital Unix C compiler, C for AIX Compiler, HP-UX C compiler,
dnl and IRIX C compiler.
dnl
dnl @version $Id: ac_prog_cc_no_writeable_strings.m4,v 1.1 2002/02/20 16:18:18 steve Exp $
dnl @author Guido Draheim <guidod@gmx.de>

dnl  This is an older version of ax_cflags_no_writable_strings.m4
dnl  which is nowadays to be found in the Autoconf Archive.  Nowadays,
dnl  this file has this permission notice there::
dnl
dnl  Copyright (c) 2008 Guido U. Draheim <guidod@gmx.de>
dnl
dnl  This program is free software; you can redistribute it and/or modify it
dnl  under the terms of the GNU General Public License as published by the
dnl  Free Software Foundation; either version 3 of the License, or (at your
dnl  option) any later version.
dnl
dnl  This program is distributed in the hope that it will be useful, but
dnl  WITHOUT ANY WARRANTY; without even the implied warranty of
dnl  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
dnl  Public License for more details.
dnl
dnl  You should have received a copy of the GNU General Public License along
dnl  with this program. If not, see <https://www.gnu.org/licenses/>.
dnl
dnl  As a special exception, the respective Autoconf Macro's copyright owner
dnl  gives unlimited permission to copy, distribute and modify the configure
dnl  scripts that are the output of Autoconf when processing the Macro. You
dnl  need not follow the terms of the GNU General Public License when using
dnl  or distributing such scripts, even though portions of the text of the
dnl  Macro appear in them. The GNU General Public License (GPL) does govern
dnl  all other use of the material that constitutes the Autoconf Macro.
dnl
dnl  This special exception to the GPL applies to versions of the Autoconf
dnl  Macro released by the Autoconf Archive. When you make and distribute a
dnl  modified version of the Autoconf Macro, you may extend this special
dnl  exception to the GPL to apply to your modified version as well.


AC_DEFUN([AC_PROG_CC_NO_WRITEABLE_STRINGS], [
  pushdef([CV],ac_cv_prog_cc_no_writeable_strings)dnl
  hard=$2
  if test -z "$hard"; then
    msg="C to warn about writing to stringliterals"
  else
    msg="C to prohibit any write to stringliterals"
  fi
  AC_CACHE_CHECK($msg, CV, [
  cat > conftest.c <<EOF
#include <string.h>
int main (void)
{
   char test[[16]];
   if (strcpy (test, "test")) return 0;
   return 1;
}
EOF
  dnl GCC
  if test "$GCC" = "yes"; 
  then
  	if test -z "$hard"; then
      	    CV="-Wwrite-strings"
        else
            CV="-fno-writable-strings -Wwrite-strings"
        fi

        if test -n "`${CC-cc} -c $CV conftest.c 2>&1`" ; then
            CV="suppressed: string.h"
        fi

  dnl Solaris C compiler
  elif  $CC -flags 2>&1 | grep "Xc.*strict ANSI C" > /dev/null 2>&1 &&
	$CC -c -xstrconst conftest.c > /dev/null 2>&1 &&
	test -f conftest.o 
  then
        # strings go into readonly segment
	CV="-xstrconst"

	rm conftest.o
        if test -n "`${CC-cc} -c $CV conftest.c 2>&1`" ; then
             CV="suppressed: string.h"
        fi
  
  dnl HP-UX C compiler
  elif  $CC > /dev/null 2>&1 &&
	$CC -c +ESlit conftest.c > /dev/null 2>&1 &&
	test -f conftest.o 
  then
       # strings go into readonly segment
	CV="+ESlit"
	
	rm conftest.o
        if test -n "`${CC-cc} -c $CV conftest.c 2>&1`" ; then
             CV="suppressed: string.h"
        fi

  dnl Digital Unix C compiler
  elif ! $CC > /dev/null 2>&1 &&
	$CC -c -readonly_strings conftest.c > /dev/null 2>&1 &&
	test -f conftest.o
  then	
       # strings go into readonly segment
	CV="-readonly_strings"
	
	rm conftest.o
        if test -n "`${CC-cc} -c $CV conftest.c 2>&1`" ; then
             CV="suppressed: string.h"
        fi

  dnl C for AIX Compiler

  dnl IRIX C compiler
	# -use_readonly_const is the default for IRIX C, 
	# puts them into .rodata, but they are copied later.
	# need to be "-G0 -rdatashared" for strictmode but
	# I am not sure what effect that has really.

  fi
  rm -f conftest.*
  ])
  if test -z "[$]$1" ; then
    if test -n "$CV" ; then
      case "$CV" in
        suppressed*) $1="" ;; # known but suppressed
        *)  $1="$CV" ;;
      esac
    fi
  fi
  AC_SUBST($1)
  popdef([CV])dnl
])


