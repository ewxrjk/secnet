# subdirmk - useful rules for clean target
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later

&CLEAN += & *~ *.tmp
&CLEAN += $(&OBJECTS)
&CLEAN += $(&DEPFILES)
&CLEAN += $(&TARGETS)

# &TARGETS_clean

&/clean::
	$(RM) $(&CLEAN)
