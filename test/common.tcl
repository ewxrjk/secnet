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

set extra(inside) {
    local-mobile True;
    mtu-target 1260;
}
set extra(outside) {}

proc mkconf {which} {
    global tmp
    global netlink
    global ports
    global extra
    global netlinkfh
    set pipefp $tmp/$which.netlink
    foreach tr {t r} {
	file delete $pipefp.$tr
	exec mkfifo -m600 $pipefp.$tr
	set netlinkfh($which.$tr) [set fh [open $pipefp.$tr r+]]
	fconfigure $fh -blocking 0 -buffering none -translation binary
    }
    fileevent $netlinkfh($which.r) readable [list netlink-readable $which]
    set fakeuf $tmp/$which.fake-userv
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
	netlink userv-ipif {
	    name \"netlink\";
            userv-path \"$fakeuf\";
	$netlink($which)
	    mtu 1400;
	    buffer sysbuffer(2048);
	    interface \"secnet-test-[string range $which 0 0]\";
        };
        comm
"
    set delim {}
    foreach port $ports($which) {
	append cfg "$delim
	    udp {
                port $port;
                address \"::1\", \"127.0.0.1\";
		buffer sysbuffer(4096);
	    }
	"
        set delim ,
    }
    append cfg ";
	local-name \"test-example/$which/$which\";
	local-key rsa-private(\"test-example/$which.key\");
"
    append cfg $extra($which)
    append cfg {
	log logfile {
	    filename "/dev/tty";
	    class "info","notice","warning","error","security","fatal";
	};
	system {
	};
	resolver adns {
	};
	log-events "all";
	random randomfile("/dev/urandom",no);
	transform eax-serpent { }, serpent256-cbc { };
	include test-example/sites.conf
	sites map(site,vpn/test-example/all-sites);
    }
    return $cfg
}

proc spawn-secnet {which} {
    global netlinkfh
    global tmp
    upvar #0 pids($which) pid
    set cf $tmp/$which.conf
    set ch [open $cf w]
    puts $ch [mkconf $which]
    close $ch
    set argl [list strace -o$tmp/$which.strace ./secnet -dvnc $cf]
    set pid [fork]
    if {!$pid} {
	execl [lindex $argl 0] [lrange $argl 1 end]
    }
    puts -nonewline $netlinkfh($which.t) [hbytes h2raw c0]
}

proc netlink-readable {which} {
    global ok
    upvar #0 netlinkfh($which.r) fh
    read $fh; # empty the buffer
    switch -exact $which {
	inside {
	    puts OK
	    set ok 1; # what a bodge
	    return
	}
	outside {
	    error "inside rx'd!"
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
    exit 1
}

proc sendpkt {} {
    global netlinkfh
    set p {
        4500 0054 ed9d 4000 4001 24da ac12 e809
        ac12 e802 0800 1de4 2d96 0001 f1d4 a05d
        0000 0000 507f 0b00 0000 0000 1011 1213
        1415 1617 1819 1a1b 1c1d 1e1f 2021 2223
        2425 2627 2829 2a2b 2c2d 2e2f 3031 3233
        3435 3637
    }
    puts -nonewline $netlinkfh(inside.t) \
	[hbytes h2raw c0[join $p ""]c0]
}

file mkdir test/tmp
set tmp test/tmp
set socktmp $tmp
regsub {^(?!/)} $socktmp {./} socktmp ;# dgram-socket wants ./ or /

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
