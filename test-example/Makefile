all: sites.conf inside.key outside.key

%.key: %.key.b64
	base64 -d <$< >$@.new && mv -f $@.new $@

sites.conf: ../make-secnet-sites sites Makefile
	../make-secnet-sites sites sites.conf
