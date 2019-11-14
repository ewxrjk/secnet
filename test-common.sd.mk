
include common.make

&TESTSCRIPTS ?= $(shell echo &^/t-*[0-9a-z])
&TESTNAMES := $(patsubst t-%,%,$(notdir $(&TESTSCRIPTS)))

&DEPS += $(src)/test-common.tcl
&DEPS += $(src)/common.make
&DEPS += $(src)/test-common.sd.mk
&DEPS += &/Subdir.mk

&TARGETS += &check

&check-real: $(foreach t,$(&TESTNAMES),&d-$t/ok)

&d-%/ok: &^/t-% $(&DEPS)
	@rm -rf &d-$*; mkdir &d-$*
	@export SECNET_TEST_BUILDDIR=$(topbuilddir); \
	 export PYTHONBYTECODEBASE=/dev/null; \
	 cd $(src) && \
	 &^/t-$* >&d-$*/log 2>\&1 \
	 || { cat &d-$*/log >\&2; false; }
	@printf "&/$* "
	@touch $@

&clean::
	$(RM) -f & *.o *.so
	$(RM) -rf & tmp
	$(RM) -rf & d-*
