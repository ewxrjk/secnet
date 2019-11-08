### -*-makefile-gmake-*-
###
### Build script for library
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

$D/all:: $D/libtoy.a
$D_CLEANFILES		:=

libtoy_SOURCES		:= $(addprefix $D/, toylib.c)
libtoy_OBJECTS		:= $(call objects, $(libtoy_SOURCES))
$(call notice-objects, $(libtoy_OBJECTS))

$D/libtoy.a: $(libtoy_OBJECTS)
	$(call v-tag,AR)ar rc $@ $^
$D_CLEANFILES		+= $D/libtoy.a

SUBDIRS			 = t
$(call descend-subdirs, $(SUBDIRS))
