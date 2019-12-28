# test cases for generate script

# some blank/comment lines to make "saw WARN" come out with 1-
# and 2-digit line numbers

WARN += 3
&WARN += 3
# $WARN
# $(WARN)
# $(&WARN)
# &$WARN

&${ some-macro, 42, $x, { &$- $(foreach something) } }

# doctests:
&:include &doctests.sd.mk
