SHELL = /bin/sh

.PHONY: all clean

all:
	ln -sf ../base91 b91enc
	ln -sf ../base91 b91dec
	$(SHELL) test.sh

clean:
	-rm -f b91??c *.b91 *.dat core
