#!/bin/sh
# subdirmk, autogen.sh (conventional autoconf invocation script)
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later
set -e
cd ${0%/*}
autoconf
