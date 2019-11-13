# subdirmk example - subdirectory rules
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later

&TARGETS_check	+= & toytest.stamp

&OBJECTS	+= & toytest.o
&LIBS		+= lib/libtoy.a

&CLEAN		+= & toytest toytest.stamp

&toytest:	$(&OBJECTS) $(&LIBS)
	$(LINK) $^

&toytest.stamp: & toytest
	$<
	touch $@
