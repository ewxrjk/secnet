# subdirmk example - subdirectory rules
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later

&TARGETS	+= & toy

&OBJECTS	+= & toy.o
&LIBS		+= lib/libtoy.a

&toy: $(&OBJECTS) $(&LIBS)
	$(LINK) $^
