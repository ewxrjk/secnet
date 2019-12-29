# subdirectory test cases

&:warn !some-unknown-warning

&:changequote &
&/

# &TARGETS_notarget += 42
&TARGETS_sometarget1
&TARGETS_sometarget2

line &\
joining

&WARN += 4
WARN += 4
&:local+global &WARN
&WARN += 5 # this warning suppressed, precisely
WARN += 5

$(NOWARN1)

&:local+global !&WARN
&WARN += 6

# doctests:
&:include &doctests.sd.mk
