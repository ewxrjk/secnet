# subdirmk example - top-level Subdir.sd.mk
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later

INCLUDES	+= -I&;lib/

include subdirmk/usual.mk
include subdirmk/regen.mk
