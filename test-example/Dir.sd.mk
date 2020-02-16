&TARGETS += & sites.conf sites-nonego.conf

include common.make

&/%.key: &^/%.key.b64
	base64 -d <$< >$@.new && mv -f $@.new $@

&sites-nonego.conf: $(src)/make-secnet-sites &^/sites &/Dir.mk
	$(src)/make-secnet-sites --output-version=1 &^/sites $@

&sites.conf: $(src)/make-secnet-sites &^/sites &/Dir.mk
	mkdir -p &pubkeys
	&~/make-secnet-sites --pubkeys-dir=&pubkeys --pubkeys-install \
		&^/sites $@.tmp && mv -f $@.tmp $@

&clean::
	rm -rf &pubkeys

&:macro &privkey
&/&$1.privkeys/priv.&$2: &/&$3
	mkdir -p $(dir $@) && cp $< $@.tmp && mv -f $@.tmp $@
&PRIVKEYS += &/&$3 &/&$1.privkeys/priv.&$2
&clean::
	rm -rf &/&$1.privkeys
&:endm

&{&privkey,outside,5dc36a4700,rsa1-sites2.key}
&{&privkey,outside,0000000000,outside.key}
&{&privkey,inside,0000000000,inside.key}

&all-privkeys:: $(&PRIVKEYS)

&TARGETS += $(&PRIVKEYS)
&CLEAN += *.new
