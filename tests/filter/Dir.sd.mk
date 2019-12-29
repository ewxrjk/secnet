# test cases for generate script

# some blank/comment lines to make "saw WARN" come out with 1-
# and 2-digit line numbers

WARN += 3
&WARN += 3
# $WARN
# $(WARN)
# $(&WARN)
# &$WARN

&:local+global NOWARN1 &NOWARN2
# &$NOWARN1 $(NOWARN1)
# &$NOWARN2 $(NOWARN2)

&${ some-macro, 42, $x, { &$- $(foreach something) } }

$&FBAR

# doctests:
&:include &doctests.sd.mk
