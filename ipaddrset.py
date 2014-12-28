"""IP address set manipulation, built on top of ipaddr.py"""

# This file is Free Software.  It was originally written for secnet.
#
# Copyright 2014 Ian Jackson
#
# You may redistribute secnet as a whole and/or modify it under the
# terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3, or (at your option) any
# later version.
#
# You may redistribute this file and/or modify it under the terms of
# the GNU General Public License as published by the Free Software
# Foundation; either version 2, or (at your option) any later version.
# Note however that this version of ipaddrset.py uses the Python
# ipaddr library from Google, which is licenced only under the Apache
# Licence, version 2.0, which is only compatible with the GNU GPL v3
# (or perhaps later versions), and not with the GNU GPL v2.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software; if not, see
# https://www.gnu.org/licenses/gpl.html.

import ipaddr

_vsns = [6,4]

class IPAddressSet:
	"A set of IP addresses"

	# constructors
	def __init__(self,l=[]):
		"New set contains each ipaddr.IPNetwork in the sequence l"
		self._v = {}
		for v in _vsns:
			self._v[v] = [ ]
		self.append(l)

	# housekeeping and representation
	def _compact(self):
		for v in _vsns:
			self._v[v] = ipaddr.collapse_address_list(self._v[v])
	def __repr__(self):
		return "IPAddressSet(%s)" % self.networks()
	def str(self,comma=",",none="-"):
		"Human-readable string with controllable delimiters"
		if self:
			return comma.join(map(str, self.networks()))
		else:
			return none
	def __str__(self):
		return self.str()

	# mutators
	def append(self,l):
		"Appends each ipaddr.IPNetwork in the sequence l to self"
		self._append(l)
		self._compact()

	def _append(self,l):
		"Appends each ipaddr.IPNetwork in the sequence l to self"
		for a in l:
			self._v[a.version].append(a)

	# enquirers including standard comparisons
	def __nonzero__(self):
		for v in _vsns:
			if self._v[v]:
				return True
		return False

	def __eq__(self,other):
		for v in _vsns:
			if self._v[v] != other._v[v]:
				return False
		return True
	def __ne__(self,other): return not self.__eq__(other)
	def __ge__(self,other):
		"""True iff self completely contains IPAddressSet other"""
		for o in other:
			if not self._contains_net(o):
				return False
		return True
	def __le__(self,other): return other.__ge__(self)
	def __gt__(self,other): return self!=other and other.__ge__(self)
	def __lt__(self,other): return other.__gt__(self)

	def __cmp__(self,other):
		if self==other: return 0
		if self>=other: return +1
		if self<=other: return -1
		return NotImplemented

	def __iter__(self):
		"Iterates over minimal list of distinct IPNetworks in this set"
		for v in _vsns:
			for i in self._v[v]:
				yield i

	def networks(self):
		"Returns miminal list of distinct IPNetworks in this set"
		return [i for i in self]

	# set operations
	def intersection(self,other):
		"Returns the intersection; does not modify self"
		r = IPAddressSet()
		for v in _vsns:
			for i in self._v[v]:
				for j in other._v[v]:
					if i.overlaps(j):
						if i.prefixlen > j.prefixlen:
							r._append([i])
						else:
							r._append([j])
		return r
	def union(self,other):
		"Returns the union; does not modify self"
		r = IPAddressSet()
		r._append(self.networks())
		r._append(other.networks())
		r._compact()
		return r

	def _contains_net(self,n):
		"""True iff self completely contains IPNetwork n"""
		for i in self:
			if i.overlaps(n) and n.prefixlen >= i.prefixlen:
				return True
		return False

	def contains(self,thing):
		"""Returns True iff self completely contains thing.
		   thing may be an IPNetwork or an IPAddressSet"""
		try:
			v = [thing.version]
		except KeyError:
			v = None
		if v:
			return self._contains_net(ipaddr.IPNetwork(thing))
		else:
			return self.__ge__(thing)

def complete_set():
	"Returns a set containing all addresses"
	s=IPAddressSet()
	for v in _vsns:
		a=ipaddr.IPAddress(0,v)
		n=ipaddr.IPNetwork("%s/0" % a)
		s.append([n])
	return s
