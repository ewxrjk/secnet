# subdirmk - part of the test suite
#  Copyright 2019 Mark Wooding
#  Copyright 2019 Ian Jackson
# SPDX-License-Identifier: LGPL-2.0-or-later
# There is NO WARRANTY.

TESTS=$(wildcard tests/*/check)

all: $(addsuffix .done, $(TESTS))

.PHONY: tests/%/check.done all

tests/%/check.done:
	tests/$*/check >tests/$*/log 2>&1
	@echo $* ok.
