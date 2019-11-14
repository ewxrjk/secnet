
&TARGETS += & udp-preload.so

&DEPS += & udp-preload.so
&DEPS += &^ common.tcl
&DEPS += secnet
&DEPS += test-example/sites.conf
&DEPS += test-example/inside.key
&DEPS += test-example/outside.key

&:include test-common.sd.mk

&OBJECTS += & udp-preload.o

$(&OBJECTS) : ALL_CFLAGS += -D_REENTRANT -fPIC

&udp-preload.so: $(&OBJECTS)
	$(CC) -shared -Wl,-soname,$@.1 $^ -o $@ -ldl

# These test scripts use little cpu but contain sleeps etc.  So when
# there are several, we are going to want to run *loads* in parallel.
#
# Ideally we would do something like "every one of these counts for a
# tenth of a job" but make can't do that.  So bodge it: we treat all the
# tests as a single job, and disconnect the parent's jobserver.
#
# make.info says $(MAKE) causes special handling of the rule but only
# if it's written literally like that in the rule, hence this
# indirection.  We need no squash MAKEFLAGS and MFLAGS too.
# MAKELEVEL seems like it will be fine to pass on.

MAKE_NOTSPECIAL:=$(MAKE)

&check:: $(&DEPS)
	env -u MAKEFLAGS -u MFLAGS \
	$(MAKE_NOTSPECIAL) -j$(shell nproc || 1)0 &check-real

&:include subdirmk/cdeps.sd.mk
