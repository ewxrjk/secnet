#!/usr/bin/python

import ipaddr
from ipaddr import IPNetwork, IPAddress

import ipaddrset
from ipaddrset import IPAddressSet

v4a=IPAddress('172.18.45.6')

s=IPAddressSet()
print 's =', s
s.append([IPNetwork('172.18.45.0/24')])
s.append([IPNetwork('2001:23:24::/40')])
print s

t=IPAddressSet(map(IPNetwork,['172.31.80.8/32','172.18.45.192/28']))
print 't =', t
print t <= s
print t == s

for n1s in ['172.18.44.0/23','172.18.45.6/32','172.18.45.0/24']:
    n1=IPNetwork(n1s)
    print n1
    print s.contains(n1)
    print t.contains(n1)

n=s.networks()[0]

a=ipaddrset.complete_set()
print 'a =', a
print a >= s
print a >= t

print '^'
print s.intersection(t)
print t.intersection(s)

print 'u'
print s.union(t)
print t.union(s)
