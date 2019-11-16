&TARGETS += & sites.conf inside.key outside.key rsa1-sites2.key all-privkeys

include common.make

&/%.key: &^/%.key.b64
	base64 -d <$< >$@.new && mv -f $@.new $@

&sites.conf: $(src)/make-secnet-sites &^/sites &/Dir.mk
	$(src)/make-secnet-sites &^/sites $@

define privkey
&/$1.privkeys/priv.$2: &/$3
	mkdir -p $$(dir $$@) && cp $$< $$@.tmp && mv -f $$@.tmp $$@
&all-privkeys:: &/$1.privkeys/priv.$2
&clean::
	rm -rf &/$1.privkeys
endef

$(eval $(call privkey,outside,5dc36a4700,rsa1-sites2.key))
$(eval $(call privkey,outside,0000000000,outside.key))
$(eval $(call privkey,inside,0000000000,inside.key))

&CLEAN += *.new
