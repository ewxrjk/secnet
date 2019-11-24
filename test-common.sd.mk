
include common.make

&TESTSCRIPTS ?= $(shell echo &^/t-*[0-9a-z])
&TESTNAMES := $(patsubst t-%,%,$(notdir $(&TESTSCRIPTS)))

&DEPS += $(src)/test-common.tcl
&DEPS += common.make
&DEPS += $(src)/test-common.sd.mk
&DEPS += &/Subdir.mk

&check-real: $(foreach t,$(&TESTNAMES),&d-$t/ok)

CHECK_SILENT ?= @

&d-%/ok: &^/t-% $(&DEPS)
	$(CHECK_SILENT) rm -rf &d-$*; mkdir &d-$*
	$(CHECK_SILENT) export SECNET_TEST_BUILDDIR=$(topbuilddir); \
	 export PYTHONBYTECODEBASE=/dev/null; \
	 cd $(src) && \
	 &/t-$* >$(topbuilddir)/&/d-$*/log 2>\&1 \
	 || { cat $(topbuilddir)/&/d-$*/log >\&2; false; }
	$(CHECK_SILENT) printf "&/$* "
	$(CHECK_SILENT) touch $@

&CLEAN += & *.so

&clean::
	$(RM) -rf & tmp
	$(RM) -rf & d-*
