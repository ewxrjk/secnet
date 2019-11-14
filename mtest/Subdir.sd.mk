
&DEPS += $(src)/make-secnet-sites
&DEPS += $(src)/ipaddrset.py
&DEPS += &^/common.tcl

&:include test-common.sd.mk

&check:: &check-real
