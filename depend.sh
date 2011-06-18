#!/bin/sh

# For more information see "Recursive Make Considered Harmful" at
# http://www.canb.auug.org.au/~millerp/rmch/recu-make-cons-harm.html

set -e
set -u

cutout="$1"
shift

# cutout may contain the character '.' which means a special thing to sed
# Escape all '.'s (i.e. '..' -> '\.\.')
cutout2="`echo ${cutout} | sed -e 's@\.@\\\.@g'`"

# We don't bother depending on system header files (which have names
# starting with '/'). We arrange for both the .o and the .d file to depend
# on the appropriate header files. We're using VPATH, so we turn pathnames
# of the form "${srcdir}/foo" into just "foo" (we expect srcdir to be
# passed as our first command line argument)
gcc -M -MG "$@" |
sed -e 's@ /[^ ]*@@g' -e 's@^\(.*\)\.o:@\1.d \1.o:@' -e "s@${cutout2}/@@g"
