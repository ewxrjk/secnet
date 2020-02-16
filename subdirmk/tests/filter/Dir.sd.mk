&# subdirmk - test cases for generate script
&# Copyright various contributors - see top level README.
&# SPDX-License-Identifier: LGPL-2.0-or-later
&# There is NO WARRANTY.

WARN += 3
&WARN += 3
# $WARN
# $(WARN)
# $(&WARN)
# &$WARN

&:local+global NOWARN1 &NOWARN2
# &$NOWARN1 $(NOWARN1)
# &$NOWARN2 $(NOWARN2)

&{ some-macro, 42, $x, { &$- $(foreach something) } }

$&FBAR

# doctests:
&:include &doctests.sd.mk
