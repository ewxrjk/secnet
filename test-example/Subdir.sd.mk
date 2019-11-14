TARGETS=sites.conf inside.key outside.key

VPATH:=@srcdir@
include ../common.make
srcdir:=@srcdir@
topdir:=@top_srcdir@

all: $(TARGETS)

%.key: %.key.b64
	base64 -d <$< >$@.new && mv -f $@.new $@

sites.conf: $(topdir)/make-secnet-sites $(srcdir)/sites Makefile
	$(topdir)/make-secnet-sites $(srcdir)/sites sites.conf

clean:
	rm -f *~ ./#*# *.new $(TARGETS)
