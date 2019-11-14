
&DEPS += &~/make-secnet-sites
&DEPS += &~/ipaddrset.py
&DEPS += &^/common.tcl

&:include test-common.sd.mk

&check:: &check-real
