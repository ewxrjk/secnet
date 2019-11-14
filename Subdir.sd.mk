# Makefile for secnet
#
# This file is part of secnet.
# See README for full list of copyright holders.
#
# secnet is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
# 
# secnet is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# version 3 along with secnet; if not, see
# https://www.gnu.org/licenses/gpl.html.

.PHONY:	all clean realclean distclean dist install

PACKAGE:=secnet
VERSION=0.5.0

VPATH:=@srcdir@
srcdir:=@srcdir@
include common.make

INSTALL:=@INSTALL@
INSTALL_PROGRAM:=@INSTALL_PROGRAM@
INSTALL_SCRIPT:=@INSTALL_SCRIPT@
INSTALL_DATA:=@INSTALL_DATA@

prefix:=$(DESTDIR)@prefix@
exec_prefix:=@exec_prefix@
sbindir:=@sbindir@
sysconfdir:=$(DESTDIR)@sysconfdir@
datarootdir:=@datarootdir@
transform:=@program_transform_name@
mandir:=@mandir@

ALL_CFLAGS:=@DEFS@ -I$(srcdir) -I. $(CFLAGS) $(EXTRA_CFLAGS)
CPPFLAGS:=@CPPFLAGS@ -DDATAROOTDIR='"$(datarootdir)"' $(EXTRA_CPPFLAGS)
LDFLAGS:=@LDFLAGS@ $(EXTRA_LDFLAGS)
LDLIBS:=@LIBS@ $(EXTRA_LDLIBS)

TARGETS:=secnet

OBJECTS:=secnet.o util.o conffile.yy.o conffile.tab.o conffile.o modules.o \
	resolver.o random.o udp.o site.o transform-cbcmac.o transform-eax.o \
	comm-common.o polypath.o \
	netlink.o rsa.o dh.o serpent.o serpentbe.o \
	md5.o sha512.o tun.o slip.o sha1.o ipaddr.o log.o \
	process.o @LIBOBJS@ \
	hackypar.o
# version.o is handled specially below and in the link rule for secnet.

PYMODULES := ipaddrset.py argparseactionnoyes.py

TEST_OBJECTS:=eax-aes-test.o eax-serpent-test.o eax-serpentbe-test.o \
		eax-test.o aes.o

ifeq (version.o,$(MAKECMDGOALS))
OBJECTS:=version.o
TEST_OBJECTS:=
endif

STALE_PYTHON_FILES=	$(foreach e, py pyc, \
			$(foreach p, /usr /usr/local, \
			$(foreach l, ipaddr, \
			$(DESTDIR)$p/share/secnet/$l.$e \
			)))

%.c:	%.y

%.yy.c:	%.fl
	flex --header=$*.yy.h -o$@ $<

%.tab.c %.tab.h:	%.y
	bison -d -o $@ $<

%.o: %.c conffile.yy.h
	$(CC) $(CPPFLAGS) $(ALL_CFLAGS) -c $< -o $@

all::	$(TARGETS) check

${srcdir}/config.h.in: configure.ac
	cd ${srcdir} && autoheader
	touch $@

MAKEFILE_TEMPLATES += config.h.in
CONFIG_STATUS_OUTPUTS += config.h

# C and header file dependency rules
SOURCES:=$(OBJECTS:.o=.c) $(TEST_OBJECTS:.o=.c)
DEPENDS:=$(OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)

-include *.d

# Manual dependencies section
conffile.yy.c:	conffile.fl conffile.tab.c
conffile.yy.h:	conffile.yy.c
conffile.tab.c:	conffile.y
# End of manual dependencies section

conffile.yy.o: ALL_CFLAGS += -Wno-sign-compare

secnet:	$(OBJECTS)
	$(MAKE) version.o # *.o $(filter-out %.o, $^)
	$(CC) $(LDFLAGS) $(ALL_CFLAGS) -o $@ $(OBJECTS) version.o $(LDLIBS)
# We (always) regenerate the version, but only if we regenerate the
# binary.  (This is necessary as the version string is can depend on
# any of the source files, eg to see whether "+" is needed.)

ifneq (,$(wildcard .git/HEAD))
# If we have (eg) committed, relink and thus regenerate the version
# with the new info from git describe.
secnet: Makefile .git/HEAD $(shell sed -n 's#^ref: #.git/#p' .git/HEAD)
secnet: $(wildcard .git/packed-refs)
endif

TESTDIRS=stest mtest

FAST_CHECKS= eax-aes-test.confirm eax-serpent-test.confirm \
	eax-serpentbe-test.confirm check-ipaddrset \
	$(addsuffix /check,$(TESTDIRS))

CHECKS += $(FAST_CHECKS)
CHECKS += msgcode-test.confirm

check: $(CHECKS)

recheck:
	rm -f $(FAST_CHECKS)
	rm -rf $(addsuffix /d-*, $(TESTDIRS))
	$(MAKE) check

version.c: Makefile
	echo "#include \"secnet.h\"" >$@.new
	@set -ex; if test -e .git && type -p git >/dev/null; then \
		v=$$(git describe --match 'v*'); v=$${v#v}; \
		if ! git diff --quiet HEAD; then v="$$v+"; fi; \
	else \
		v="$(VERSION)"; \
	fi; \
	echo "char version[]=\"secnet $$v\";" >>$@.new
	mv -f $@.new $@

eax-%-test: eax-%-test.o eax-test.o %.o
	$(CC) $(LDFLAGS) $(ALL_CFLAGS) -o $@ $^

eax-%-test.confirm: eax-%-test eax-%-test.vectors
	./$< <$(srcdir)/eax-$*-test.vectors >$@.new
	mv -f $@.new $@

msgcode-test: msgcode-test.o
	$(CC) $(LDFLAGS) $(ALL_CFLAGS) -o $@ $^

msgcode-test.confirm: msgcode-test
	./msgcode-test
	touch $@

check-ipaddrset: ipaddrset-test.py ipaddrset.py ipaddrset-test.expected
	$(srcdir)/ipaddrset-test.py >ipaddrset-test.new
	diff -u $(srcdir)/ipaddrset-test.expected ipaddrset-test.new

.PRECIOUS: eax-%-test

installdirs:
	$(INSTALL) -d $(prefix)/share/secnet $(sbindir)
	$(INSTALL) -d $(mandir)/man8
	$(INSTALL) -d $(datarootdir)/secnet

install: installdirs
	set -e; ok=true; for f in $(STALE_PYTHON_FILES); do \
		if test -e $$f; then \
			echo >\&2 "ERROR: $$f still exists "\
				"- try \`make install-force'"; \
			ok=false; \
		fi; \
	done; \
	$$ok
	$(INSTALL_PROGRAM) secnet $(sbindir)/`echo secnet|sed '$(transform)'`
	$(INSTALL_PROGRAM) ${srcdir}/make-secnet-sites $(sbindir)/`echo make-secnet-sites|sed '$(transform)'`
	set -e; for m in $(PYMODULES); do \
		$(INSTALL_DATA) ${srcdir}/$$m $(prefix)/share/secnet/$$m; \
		done
	$(INSTALL_SCRIPT) ${srcdir}/polypath-interface-monitor-linux \
		$(datarootdir)/secnet/.
	$(INSTALL_DATA) ${srcdir}/secnet.8 $(mandir)/man8/secnet.8

install-force:
	rm -f $(STALE_PYTHON_FILES)
	$(MAKE) install

clean::
	$(RM) -f *.o *.yy.[ch] *.tab.[ch] $(TARGETS) core version.c
	$(RM) -f *.d *.pyc *~ eax-*-test.confirm eax-*-test
	$(RM) -rf __pycache__
	$(RM) -f msgcode-test.confirm msgcode-test

realclean::	clean
	$(RM) -f *~ Makefile config.h  *.d \
	config.log config.status config.cache \
	config.stamp Makefile.bak

distclean::	realclean

include subdirmk/regen.mk

# Release checklist:
#
#  0. Use this checklist from Makefile.in
#
#  1. Check that the tree has what you want
#
#  2. Update changelog:
#         gbp dch --since=<PREVIOUS VERSION>
#     and then edit debian/changelog.
#
#  3. Update VERSION (in this file, above) and
#     finalise debian/changelog (removing ~ from version) and commit.
#
#  4. Build source and binaries:
#       dgit -wgf sbuild -A -c stretch -j8
#
#  5. dpkg -i on zealot just to check
#       dpkg -i ~ian/things/Fvpn/bpd/secnet_${VERSION}_amd64.deb
#
#  6. run it on chiark
#     check we can still ping davenant and chiark
#
#  7. Make git tag and source tarball signature:
#       git-tag -u general -m "secnet $VERSION" -s v${VERSION//\~/_}
#       gpg -u general --detach-sign ../bpd/secnet_$VERSION.tar.gz
#
#  8. Publish the branch and distriubtion files:
#       git-push origin v${VERSION//\~/_} v${VERSION//\~/_}~0:master
#       dcmd rsync -v ../bpd/secnet_${VERSION}_multi.changes chiark:/home/ianmdlvl/public-html/secnet/download/
#
#  9. Sort out html.  On chiark as user secnet:
#       cd ~secnet/public-html/release/
#       mkdir $VERSION
#       cd $VERSION
#       ln -s /home/ianmdlvl/public-html/secnet/download/secnet?$VERSION* .
#       ln -sfn $VERSION ../current
#
# 10. write and post a release announcement
#       cd ../bpd
#       dcmd sha256sum secnet_${VERSION}_multi.changes
#       ...
#       gpg --clearsign ../release-announcement
#       rsync -vP ../release-announcement.asc c:mail/d/
#
# 11. bump changelog version in master, to new version with ~
