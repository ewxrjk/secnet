#!/usr/bin/python

# This file is Free Software.  It was originally written for secnet.
#
# Copyright 2014 Ian Jackson
#
# You may redistribute secnet as a whole and/or modify it under the
# terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3, or (at your option) any
# later version.
#
# You may redistribute this fileand/or modify it under the terms of
# the GNU General Public License as published by the Free Software
# Foundation; either version 2, or (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software; if not, see
# https://www.gnu.org/licenses/gpl.html.
#
# The corresponding test vector file ise ipaddrset-test.expected.  I
# don't believe it is a creative work that attracts copyright.  -iwj.

from __future__ import print_function
from __future__ import unicode_literals

import ipaddress
from ipaddress import ip_network, ip_address

import ipaddrset
from ipaddrset import IPAddressSet

v4a=ip_address('172.18.45.6')

s=IPAddressSet()
print('s =', s)
s.append([ip_network('172.18.45.0/24')])
s.append([ip_network('2001:23:24::/48')])
print(s)

t=IPAddressSet(map(ip_network,['172.31.80.8/32','172.18.45.192/28']))
print('t =', t)
print(t <= s)
print(t == s)

for n1s in ['172.18.44.0/23','172.18.45.6/32','172.18.45.0/24']:
    n1=ip_network(n1s)
    print(n1)
    print(s.contains(n1))
    print(t.contains(n1))

n=s.networks()[0]

a=ipaddrset.complete_set()
print('a =', a)
print(a >= s)
print(a >= t)

print('^')
print(s.intersection(t))
print(t.intersection(s))

print('u')
print(s.union(t))
print(t.union(s))
