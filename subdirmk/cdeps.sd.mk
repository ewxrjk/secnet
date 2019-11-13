# subdirmk - useful rules for making and using cpp .*.d files
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later

CDEPS_CFLAGS ?= -MD -MF $(*D)/.$(*F).d

&DEPFILES += $(foreach b,$(patsubst %.o,%,$(&OBJECTS)), \
		$(dir $b).$(notdir $b).d)
-include $(&DEPFILES)

&CLEAN += $(&DEPFILES)
