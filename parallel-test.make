
# usage
#  ../parallel-bisect.sh

DIRS := $(wildcard d.*)

TARGETS := $(addsuffix /done, $(DIRS))

all: $(TARGETS)

%/done:
	set -e; SECNET_TEST_BUILDDIR=$(PWD)/$* ./stest/t-nonnego-oo
