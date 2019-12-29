
TESTS=$(wildcard tests/*/check)

all: $(addsuffix .done, $(TESTS))

.PHONY: tests/%/check.done all

tests/%/check.done:
	tests/$*/check >tests/$*/log 2>&1
	@echo $* ok.
