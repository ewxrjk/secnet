TARGETS=sites.conf inside.key outside.key

all: $(TARGETS)

%.key: %.key.b64
	base64 -d <$< >$@.new && mv -f $@.new $@

sites.conf: ../make-secnet-sites sites Makefile
	../make-secnet-sites sites sites.conf

clean:
	rm -f *~ ./#*# *.new $(TARGETS)
