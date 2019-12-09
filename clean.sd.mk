# subdirmk - useful rules for clean target
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later

&# Usage:
&#   &:include subdirmk/clean.sd.mk
&# (probably in Perdir.sd.mk)
&#
&# Provides a per-directory `clean' target, which deletes all the files
&# in &CLEAN.  &OBJECTS, &DEPFILES and &TARGETS are automatically deleted.
&#
&# If you want to delete a directory, extend the target with
&#   &/clean::
&#	$(RM) -r somethingn
&# ($(RM) conventionally contains `-f'.)

&CLEAN += & *~ .*~ *.tmp
&CLEAN += $(&OBJECTS)
&CLEAN += $(&TARGETS)

&TARGETS_clean +=

&/clean::
	$(RM) $(&CLEAN)
