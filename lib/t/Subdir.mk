### -*-makefile-gmake-*-
###
### Build script for library test
###
### (c) 2019 Mark Wooding
###

###----- Licensing notice ---------------------------------------------------
###
### This program is free software; you can redistribute it and/or modify
### it under the terms of the GNU Library General Public License as
### published by the Free Software Foundation; either version 2 of the
### License, or (at your option) any later version.
###
### This program is distributed in the hope that it will be useful,
### but WITHOUT ANY WARRANTY; without even the implied warranty of
### MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
### GNU Library General Public License for more details.
###
### You should have received a copy of the GNU Library General Public
### License along with this program; if not, write to the Free
### Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
### MA 02111-1307, USA.

$D_CLEANFILES		:=

$D/check:: $D/toytest.stamp

toytest_SOURCES		:= $(addprefix $D/, toytest.c)
toytest_OBJECTS		:= $(call objects, $(toytest_SOURCES))
toytest_LIBS		 = lib/libtoy.a
$(call notice-objects, $(toytest_OBJECTS))

$D/toytest: $(toytest_OBJECTS) $(toytest_LIBS)
	$(LINK) $^
$D_CLEANFILES		+= $D/toytest

$D/toytest.stamp: $D/toytest
	$<
	touch $@
$D_CLEANFILES		+= $D/toytest.stamp
