# subdirmk example - top-level Dir.sd.mk
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later
# There is NO WARRANTY.

INCLUDES	+= -I&^/lib/

include subdirmk/usual.mk
include subdirmk/regen.mk
