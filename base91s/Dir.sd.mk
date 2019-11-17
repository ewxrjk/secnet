
&TARGETS += & base91s base91.o
&OBJECTS += & base91.o cli.o

&CFILES += & base91.c base91.h cli.c
&CLEAN += $(&CFILES)

&base91.c: &^base91.c.patch
$(&CFILES): &/%: &~/base91-c/% &/Dir.mk
	perl -pe <$< >$@.tmp \
 'next if m{^\#include}; s/basE91/base91s/g; s/base91\b/base91s/g'
	patch <$(or $(filter %.patch,$^),/dev/null) $@.tmp
	mv -f $@.tmp $@

$(&OBJECTS): &base91.h

&:local+global &LDFLAGS &LDLIBS

&base91s: $(&OBJECTS)
	$(CC) -o$@ $(&LDFLAGS) $^ $(&LDLIBS)
