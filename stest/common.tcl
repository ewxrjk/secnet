# This file is part of secnet.
# See LICENCE and this file CREDITS for full list of copyright holders.
# SPDX-License-Identifier: GPL-3.0-or-later
# There is NO WARRANTY.

source test-common.tcl

package require Tclx

load chiark_tcl_hbytes-1.so
load chiark_tcl_dgram-1.so

set netlink(inside) {
    local-address "172.18.232.9";
    secnet-address "172.18.232.10";
    remote-networks "172.18.232.0/28";
}
set netlink(outside) {
    local-address "172.18.232.1";
    secnet-address "172.18.232.2";
    remote-networks "172.18.232.0/28";
}

set ports(inside) {16913 16910}
set ports(outside) 16900

set defnet_v4 198.51.100
set defnet_v6 2001:db8:ff00
set defaddr_v4 ${defnet_v4}.1
set defaddr_v6 ${defnet_v6}::1

set extra(inside) {
    local-mobile True;
    mtu-target 1260;
}
set extra(outside) {}

set privkey(inside) test-example/inside.privkeys/
set privkey(outside) test-example/outside.privkeys/

set initiator inside

proc sitesconf_hook {l} { return $l }

proc oldsecnet {site} {
    upvar #0 oldsecnet($site) oldsecnet
    expr {[info exists oldsecnet] && [set oldsecnet]}
}

proc mkconf {location site} {
    global tmp
    global builddir
    global netlink
    global ports
    global extra
    global netlinkfh
    global defaddr_v4 defaddr_v6
    upvar #0 privkey($site) privkey
    set pipefp $tmp/$site.netlink
    foreach tr {t r} {
	file delete $pipefp.$tr
	exec mkfifo -m600 $pipefp.$tr
	set netlinkfh($site.$tr) [set fh [open $pipefp.$tr r+]]
	fconfigure $fh -blocking 0 -buffering none -translation binary
    }
    fileevent $netlinkfh($site.r) readable \
	[list netlink-readable $location $site]
    set fakeuf $tmp/$site.fake-userv
    set fakeuh [open $fakeuf w 0755]
    puts $fakeuh "#!/bin/sh
set -e
exec 3<&0
cat <&3 3<&- >$pipefp.r &
exec 3<>$pipefp.t
exec <$pipefp.t
exec 3<&-
exec cat
"
    close $fakeuh
    set cfg "
	hash sha1;
	netlink userv-ipif {
	    name \"netlink\";
            userv-path \"$fakeuf\";
	$netlink($site)
	    mtu 1400;
	    buffer sysbuffer(2048);
	    interface \"secnet-test-[string range $site 0 0]\";
        };
        comm
"
    set delim {}
    foreach port $ports($site) {
	append cfg "$delim
	    udp {
                port $port;
                address \"$defaddr_v6\", \"$defaddr_v4\";
		buffer sysbuffer(4096);
	    }
	"
        set delim ,
    }
    append cfg ";
	local-name \"test-example/$location/$site\";
"
    switch -glob $privkey {
	*/ {
	    set sitesconf sites.conf
	    append cfg "
	        key-cache priv-cache({
		    privkeys \"$builddir/${privkey}priv.\";
                });
"
	}
	{load-private *} {
	    set sitesconf sites-nonego.conf
	    append cfg "
		local-key load-private(\"[lindex $privkey 1]\",\"$builddir/[lindex $privkey 2]\");
"
	}
	* {
	    set sitesconf sites-nonego.conf
	    append cfg "
		local-key rsa-private(\"$builddir/$privkey\");
"
	}
    }
    set sitesconf $builddir/test-example/$sitesconf
    
    append cfg $extra($site)
    append cfg "
	log logfile {
	    prefix \"$site\";
	    class \"debug\",\"info\",\"notice\",\"warning\",\"error\",\"security\",\"fatal\";
    "
    if {[oldsecnet $site]} { append cfg "
	    filename \"/dev/stderr\";
    " }
    append cfg "
	};
    "
    append cfg {
	system {
	};
	resolver adns {
	};
	log-events "all";
	random randomfile("/dev/urandom",no);
	transform eax-serpent { }, serpent256-cbc { };
    }

    set pubkeys $tmp/$site.pubkeys
    file delete -force $pubkeys
    exec cp -rl $builddir/test-example/pubkeys $pubkeys

    set f [open $sitesconf r]
    while {[gets $f l] >= 0} {
	regsub {\"[^\"]*test-example/pubkeys/} $l "\"$pubkeys/" l
	regsub -all {\"\[127\.0\.0\.1\]\"} $l "\"\[$defaddr_v4\]\"" l
	regsub -all {\"\[::1]\"}           $l "\"\[$defaddr_v6\]\"" l
	set l [sitesconf_hook $l]
	append cfg $l "\n"
    }
    set sites [read $f]
    close $f
    append cfg $sites
    append cfg {
	sites map(site,all-sites);
    }

    return $cfg
}

proc spawn-secnet {location site} {
    global tmp
    global builddir
    global netlinkfh
    global env
    global pidmap
    global readbuf
    upvar #0 pids($site) pid
    set readbuf($site) {}
    set cf $tmp/$site.conf
    set ch [open $cf w]
    puts $ch [mkconf $location $site]
    close $ch
    set secnet $builddir/secnet
    if {[oldsecnet $site]} {
	set secnet $env(OLD_SECNET_DIR)/secnet
    }
    set argl [list $secnet -dvnc $cf]
    set divertk SECNET_STEST_DIVERT_$site
    puts "spawn:"
    foreach k [array names env] {
	switch -glob $k {
	    SECNET_STEST_DIVERT_* -
	    SECNET_TEST_BUILDDIR - OLD_SECNET_DIR { }
	    *SECNET* -
	    *PRELOAD* { puts -nonewline " $k=$env($k)" }
	}
    }
    if {[info exists env($divertk)]} {
	switch -glob $env($divertk) {
	    i - {i *} {
		regsub {^i} $env($divertk) {} divert_prefix
		puts "$divert_prefix $argl"
		puts -nonewline "run ^ command, hit return "
		flush stdout
		gets stdin
		set argl {}
	    }
	    0 - "" {
		puts " $argl"
	    }
	    /* - ./* {
		puts " $argl"
		set argl [split $env($divertk)]
		puts "... $argl"
	    }
	    * {
		error "$divertk not understood"
	    }
	}
    }
    if {[llength $argl]} { 
	set pid [fork]
	set pidmap($pid) "secnet $location/$site"
	if {!$pid} {
	    execl [lindex $argl 0] [lrange $argl 1 end]
	}
    }
    puts -nonewline $netlinkfh($site.t) [hbytes h2raw c0]
}

proc netlink-readable {location site} {
    global ok
    upvar #0 readbuf($site) buf
    upvar #0 netlinkfh($site.r) fh
    while 1 {
	set x [read $fh]
	set h [hbytes raw2h $x]
	if {![hbytes length $h]} return
	append buf $h
	#puts "READABLE $site buf=$buf"
	while {[regexp {^((?:..)*?)c0(.*)$} $buf dummy now buf]} {
	    #puts "READABLE $site now=$now (buf=$buf)"
	    regsub -all {^((?:..)*?)dbdc} $now {\1c0} now
	    regsub -all {^((?:..)*?)dbdd} $now {\1db} now
	    puts "netlink-got-packet $location $site $now"
	    netlink-got-packet $location $site $now
	}
    }
}

proc netlink-got-packet {location site data} {
    global initiator
    if {![hbytes length $data]} return 
    switch -exact $site!$initiator {
	inside!inside - outside!outside {
	    switch -glob $data {
		45000054ed9d4000fe0166d9ac12e802ac12e80900* {
		    puts "OK $data"
		    finish 0
		}
		* {
		    error "unexpected $site $data"
		}
	    }
	}
	default {
	    error "$site rx'd! (initiator $initiator)"
	}
    }
}

proc bgerror {message} {
    global errorInfo errorCode
    catch {
	puts stderr "
----------------------------------------
$errorInfo

$errorCode
$message
----------------------------------------
    "
    }
    finish 1
}

proc sendpkt {} {
    global netlinkfh
    global initiator
    set p {
        4500 0054 ed9d 4000 4001 24da ac12 e809
        ac12 e802 0800 1de4 2d96 0001 f1d4 a05d
        0000 0000 507f 0b00 0000 0000 1011 1213
        1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
        2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
        3435 3637
    }
    puts -nonewline $netlinkfh($initiator.t) \
	[hbytes h2raw c0[join $p ""]c0]
}

set socktmp $tmp/s
exec mkdir -p -m700 $socktmp
regsub {^(?!/|\./)} $socktmp {./} socktmp ;# dgram-socket wants ./ or /

proc prefix_preload {lib} { prefix_some_path LD_PRELOAD $lib }

set env(UDP_PRELOAD_DIR) $socktmp
prefix_preload $builddir/stest/udp-preload.so

proc finish {estatus} {
    puts stderr "FINISHING $estatus"
    signal default SIGCHLD
    global pidmap
    foreach pid [array names pidmap] {
	kill KILL $pid
    }
    exit $estatus
}

proc reap {} {
    global pidmap
    #puts stderr REAPING
    foreach pid [array names pidmap] {
	set got [wait -nohang $pid]
	if {![llength $got]} continue
	set info $pidmap($pid)
	unset pidmap($pid)
	puts stderr "reaped $info: $got"
	finish 1
    }
}

signal -restart trap SIGCHLD { after idle reap }

proc udp-proxy {} {
    global socktmp udpsock
    set u $socktmp/udp
    file delete $u
    regsub {^(?!/)} $u {./} u
    set udpsock [dgram-socket create $u]
    dgram-socket on-receive $udpsock udp-relay
}

proc udp-relay {data src sock args} {
    global udpsock socktmp
    set headerlen [expr {52+1}]
    set orgsrc $src

    set dst [hbytes range $data 0 $headerlen]
    regsub {(?:00)*$} $dst {} dst
    set dst [hbytes h2raw $dst]

    hbytes overwrite data 0 [hbytes zeroes $headerlen]
    regsub {.*/} $src {} src
    set srch [hbytes raw2h $src]
    hbytes append srch 00
    if {[catch {
	if {[regexp {[^.,:0-9a-f]} $dst c]} { error "bad dst" }
	if {[hbytes length $srch] > $headerlen} { error "src addr too long" }
	hbytes overwrite data 0 $srch
	dgram-socket transmit $udpsock $data $socktmp/$dst
    } emsg]} {
	puts stderr "$orgsrc -> $dst: $emsg"
    }
}

proc adj-after {timeout args} {
    upvar #0 env(SECNET_STEST_TIMEOUT_MUL) mul
    if {[info exists mul]} { set timeout [expr {$timeout * $mul}] }
    eval after $timeout $args
}

proc test-kex {} {
    udp-proxy
    spawn-secnet in inside
    spawn-secnet out outside

    adj-after 500 sendpkt
    adj-after 1000 sendpkt
    adj-after 5000 timed-out

    vwait ok
}
