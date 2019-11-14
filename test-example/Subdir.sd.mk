&TARGETS += & sites.conf inside.key outside.key

include common.make

&/%.key: &^/%.key.b64
	base64 -d <$< >$@.new && mv -f $@.new $@

&sites.conf: $(src)/make-secnet-sites &^/sites Subdir.mk
	$(src)/make-secnet-sites &^/sites &sites.conf

&clean::
	rm -f *~ ./#*# *.new

&:include subdirmk/clean.sd.mk
