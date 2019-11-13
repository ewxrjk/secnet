# subdirmk - useful rules for making and using cpp .*.d files
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later

&# Usage:
&#   &:include subdirmk/cdeps.sd.mk
&# (probably in Perdir.sd.mk)
&#
&# Arranges for automatic #include dependency tracking for
&# C compilation.  The compiler is asked to write the dependencies to
&#  .*.d and these are automatically included.
&#
&# There is a bug: if a #included file is deleted and all references
&# in .c files to it removed, `make' will complain that it is needed
&# and can't be built.  `make clean' will fix this.

CDEPS_CFLAGS ?= -MD -MF $(*D)/.$(*F).d

&DEPFILES += $(foreach b,$(patsubst %.o,%,$(&OBJECTS)), \
		$(dir $b).$(notdir $b).d)
-include $(&DEPFILES)

&CLEAN += $(&DEPFILES)
