# This file is part of secnet.
# See LICENCE and this file CREDITS for full list of copyright holders.
# SPDX-License-Identifier: GPL-3.0-or-later
# There is NO WARRANTY.

# usage
#  ../parallel-bisect.sh

DIRS := $(wildcard d.*)

TARGETS := $(addsuffix /done, $(DIRS))

all: $(TARGETS)

%/done:
	set -e; SECNET_TEST_BUILDDIR=$(PWD)/$* ./stest/t-nonnego-oo
