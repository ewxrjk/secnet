#! /usr/bin/env python
# Copyright (C) 2001 Stephen Early <steve@greenend.org.uk>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

"""VPN sites file manipulation.

This program enables VPN site descriptions to be submitted for
inclusion in a central database, and allows the resulting database to
be turned into a secnet configuration file.

A database file can be turned into a secnet configuration file simply:
make-secnet-sites.py [infile [outfile]]

It would be wise to run secnet with the "--just-check-config" option
before installing the output on a live system.

The program expects to be invoked via userv to manage the database; it
relies on the USERV_USER and USERV_GROUP environment variables. The
command line arguments for this invocation are:

make-secnet-sites.py -u header-filename groupfiles-directory output-file \
  group

All but the last argument are expected to be set by userv; the 'group'
argument is provided by the user. A suitable userv configuration file
fragment is:

reset
no-disconnect-hup
no-suppress-args
cd ~/secnet/sites-test/
execute ~/secnet/secnet/make-secnet-sites.py -u vpnheader groupfiles sites

This program is part of secnet. It relies on the "ipaddr" library from
Cendio Systems AB.

"""

import string
import time
import sys
import os
import ipaddr

VERSION="0.1.3"

class vpn:
	def __init__(self,name):
		self.name=name
		self.allow_defs=0
		self.locations={}
		self.defs={}

class location:
	def __init__(self,name,vpn):
		self.group=None
		self.name=name
		self.allow_defs=1
		self.vpn=vpn
		self.sites={}
		self.defs={}

class site:
	def __init__(self,name,location):
		self.name=name
		self.allow_defs=1
		self.location=location
		self.defs={}

class nets:
	def __init__(self,w):
		self.w=w
		self.set=ipaddr.ip_set()
		for i in w[1:]:
			x=string.split(i,"/")
			self.set.append(ipaddr.network(x[0],x[1],
				ipaddr.DEMAND_NETWORK))
	def subsetof(self,s):
		# I'd like to do this:
		# return self.set.is_subset(s)
		# but there isn't an is_subset() method
		# Instead we see if we intersect with the complement of s
		sc=s.set.complement()
		i=sc.intersection(self.set)
		return i.is_empty()
	def out(self):
		rn=''
		if (self.w[0]=='restrict-nets'): rn='# '
		return '%s%s %s;'%(rn,self.w[0],
			string.join(map(lambda x:'"%s/%s"'%(x.ip_str(),
				x.mask.netmask_bits_str),
				self.set.as_list_of_networks()),","))

class dhgroup:
	def __init__(self,w):
		self.w=w
	def out(self):
		return 'dh diffie-hellman("%s","%s");'%(self.w[1],self.w[2])

class hash:
	def __init__(self,w):
		self.w=w
		if (w[1]!='md5' and w[1]!='sha1'):
			complain("unknown hash type %s"%(w[1]))
	def out(self):
		return 'hash %s;'%(self.w[1])

class email:
	def __init__(self,w):
		self.w=w
	def out(self):
		return '# Contact email address: <%s>'%(self.w[1])

class num:
	def __init__(self,w):
		self.w=w
	def out(self):
		return '%s %s;'%(self.w[0],self.w[1])

class address:
	def __init__(self,w):
		self.w=w
	def out(self):
		return 'address "%s"; port %s;'%(self.w[1],self.w[2])

class rsakey:
	def __init__(self,w):
		self.w=w
	def out(self):
		return 'key rsa-public("%s","%s");'%(self.w[2],self.w[3])

class mobileoption:
	def __init__(self,w):
		self.w=w
	def out(self):
		return 'netlink-options "soft";'

def complain(msg):
	global complaints
	print ("%s line %d: "%(file,line))+msg
	complaints=complaints+1
def moan(msg):
	global complaints
	print msg;
	complaints=complaints+1

# We don't allow redefinition of properties (because that would allow things
# like restrict-nets to be redefined, which would be bad)
def set(obj,defs,w):
	if (obj.allow_defs | allow_defs):
		if (obj.defs.has_key(w[0])):
			complain("%s is already defined"%(w[0]))
		else:
			t=defs[w[0]]
			obj.defs[w[0]]=t(w)

# Process a line of configuration file
def pline(i):
	global allow_defs, group, current_vpn, current_location, current_object
	w=string.split(i)
	if len(w)==0: return
	keyword=w[0]
	if keyword=='end-definitions':
		allow_defs=0
		current_vpn=None
		current_location=None
		current_object=None
		return
	if keyword=='vpn':
		if vpns.has_key(w[1]):
			current_vpn=vpns[w[1]]
			current_object=current_vpn
		else:
			if allow_defs:
				current_vpn=vpn(w[1])
				vpns[w[1]]=current_vpn
				current_object=current_vpn
			else:
				complain("no new VPN definitions allowed")
		return
	if (current_vpn==None):
		complain("no VPN defined yet")
		return
	# Keywords that can apply at all levels
	if mldefs.has_key(w[0]):
		set(current_object,mldefs,w)
		return
	if keyword=='location':
		if (current_vpn.locations.has_key(w[1])):
			current_location=current_vpn.locations[w[1]]
			current_object=current_location
			if (group and not allow_defs and 
				current_location.group!=group):
				complain(("must be group %s to access "+
					"location %s")%(current_location.group,
					w[1]))
		else:
			if allow_defs:
				if reserved.has_key(w[1]):
					complain("reserved location name")
					return
				current_location=location(w[1],current_vpn)
				current_vpn.locations[w[1]]=current_location
				current_object=current_location
			else:
				complain("no new location definitions allowed")
		return
	if (current_location==None):
		complain("no locations defined yet")
		return
	if keyword=='group':
		current_location.group=w[1]
		return
	if keyword=='site':
		if (current_location.sites.has_key(w[1])):
			current_object=current_location.sites[w[1]]
		else:
			if reserved.has_key(w[1]):
				complain("reserved site name")
				return
			current_object=site(w[1],current_location)
			current_location.sites[w[1]]=current_object
		return
	if keyword=='endsite':
		if isinstance(current_object,site):
			current_object=current_object.location
		else:
			complain("not currently defining a site")
		return
	# Keywords that can only apply to sites
	if isinstance(current_object,site):
		if sitedefs.has_key(w[0]):
			set(current_object,sitedefs,w)
			return
	else:
		if sitedefs.has_key(w[0]):
			complain("keyword '%s' can only be used in the "
				"context of a site definition"%(w[0]))
			return
	complain("unknown keyword '%s'"%(w[0]))

def pfile(name,lines):
	global file,line
	file=name
	line=0
	for i in lines:
		line=line+1
		if (i[0]=='#'): continue
		if (i[len(i)-1]=='\n'):	i=i[:len(i)-1] # strip trailing LF
		pline(i)

def outputsites(w):
	w.write("# secnet sites file autogenerated by make-secnet-sites.py "
		+"version %s\n"%VERSION)
	w.write("# %s\n\n"%time.asctime(time.localtime(time.time())))

	# Raw VPN data section of file
	w.write("vpn-data {\n")
	for i in vpns.values():
		w.write("  %s {\n"%i.name)
		for d in i.defs.values():
			w.write("    %s\n"%d.out())
		w.write("\n")
		for l in i.locations.values():
			w.write("    %s {\n"%l.name)
			for d in l.defs.values():
				w.write("      %s\n"%d.out())
			for s in l.sites.values():
				w.write("      %s {\n"%s.name)
				w.write('        name "%s/%s/%s";\n'%
					(i.name,l.name,s.name))
				for d in s.defs.values():
					w.write("        %s\n"%d.out())
				w.write("      };\n")
			w.write("    };\n")
		w.write("  };\n")
	w.write("};\n")

	# Per-VPN flattened lists
	w.write("vpn {\n")
	for i in vpns.values():
		w.write("  %s {\n"%(i.name))
		for l in i.locations.values():
			slist=map(lambda x:"vpn-data/%s/%s/%s"%
				(i.name,l.name,x.name),
				l.sites.values())
			w.write("    %s %s;\n"%(l.name,string.join(slist,",")))
		w.write("\n    all-sites %s;\n"%
			string.join(i.locations.keys(),","))
		w.write("  };\n")
	w.write("};\n")

	# Flattened list of sites
	w.write("all-sites %s;\n"%string.join(map(lambda x:"vpn/%s/all-sites"%
		x,vpns.keys()),","))

# Are we being invoked from userv?
service=0
# If we are, which group does the caller want to modify?
group=None

vpns={}
allow_defs=1
current_vpn=None
current_location=None
current_object=None

line=0
file=None
complaints=0

# Things that can be defined at any level
mldefs={
	'dh':dhgroup,
	'hash':hash,
	'contact':email,
	'key-lifetime':num,
	'setup-retries':num,
	'setup-timeout':num,
	'wait-time':num,
	'renegotiate-time':num,
	'restrict-nets':nets
	}

# Things that can only be defined for sites
sitedefs={
	'address':address,
	'networks':nets,
	'pubkey':rsakey,
	'mobile':mobileoption
	}

# Reserved vpn/location/site names
reserved={'all-sites':None}
reserved.update(mldefs)
reserved.update(sitedefs)

# Each site must have the following defined at some level:
required={
	'dh':"Diffie-Hellman group",
	'networks':"network list",
	'pubkey':"public key",
	'hash':"hash function"
	}

if len(sys.argv)<2:
	pfile("stdin",sys.stdin.readlines())
	of=sys.stdout
else:
	if sys.argv[1]=='-u':
		if len(sys.argv)!=6:
			print "Wrong number of arguments"
			sys.exit(1)
		service=1
		header=sys.argv[2]
		groupfiledir=sys.argv[3]
		sitesfile=sys.argv[4]
		group=sys.argv[5]
		if not os.environ.has_key("USERV_USER"):
			print "Environment variable USERV_USER not found"
			sys.exit(1)
		user=os.environ["USERV_USER"]
		# Check that group is in USERV_GROUP
		if not os.environ.has_key("USERV_GROUP"):
			print "Environment variable USERV_GROUP not found"
			sys.exit(1)
		ugs=os.environ["USERV_GROUP"]
		ok=0
		for i in string.split(ugs):
			if group==i: ok=1
		if not ok:
			print "caller not in group %s"%group
			sys.exit(1)
		f=open(header)
		pfile(header,f.readlines())
		f.close()
		userinput=sys.stdin.readlines()
		pfile("user input",userinput)
	else:
		if len(sys.argv)>3:
			print "Too many arguments"
			sys.exit(1)
		f=open(sys.argv[1])
		pfile(sys.argv[1],f.readlines())
		f.close()
		of=sys.stdout
		if len(sys.argv)>2:
			of=open(sys.argv[2],'w')

# Sanity check section

# Delete locations that have no sites defined
for i in vpns.values():
	for l in i.locations.keys():
		if (len(i.locations[l].sites.values())==0):
			del i.locations[l]

# Delete VPNs that have no locations with sites defined
for i in vpns.keys():
	if (len(vpns[i].locations.values())==0):
		del vpns[i]

# Check all sites
for i in vpns.values():
	if i.defs.has_key('restrict-nets'):
		vr=i.defs['restrict-nets']
	else:
		vr=None
	for l in i.locations.values():
		if l.defs.has_key('restrict-nets'):
			lr=l.defs['restrict-nets']
			if (not lr.subsetof(vr)):
				moan("location %s/%s restrict-nets is invalid"%
					(i.name,l.name))
		else:
			lr=vr
		for s in l.sites.values():
			sn="%s/%s/%s"%(i.name,l.name,s.name)
			for r in required.keys():
				if (not (s.defs.has_key(r) or
					l.defs.has_key(r) or
					i.defs.has_key(r))):
					moan("site %s missing parameter %s"%
						(sn,r))
			if s.defs.has_key('restrict-nets'):
				sr=s.defs['restrict-nets']
				if (not sr.subsetof(lr)):
					moan("site %s restrict-nets not valid"%
						sn)
			else:
				sr=lr
			if not s.defs.has_key('networks'): continue
			nets=s.defs['networks']
			if (not nets.subsetof(sr)):
				moan("site %s networks exceed restriction"%sn)


if complaints>0:
	if complaints==1: print "There was 1 problem."
	else: print "There were %d problems."%(complaints)
	sys.exit(1)

if service:
	# Put the user's input into their group file, and rebuild the main
	# sites file
	f=open(groupfiledir+"-tmp/"+group,'w')
	f.write("# Section submitted by user %s, %s\n"%
		(user,time.asctime(time.localtime(time.time()))))
	f.write("# Checked by make-secnet-sites.py version %s\n\n"%VERSION)
	for i in userinput: f.write(i)
	f.write("\n")
	f.close()
	os.rename(groupfiledir+"-tmp/"+group,groupfiledir+"/"+group)
	# XXX rebuild main sites file!
else:
	outputsites(of)
