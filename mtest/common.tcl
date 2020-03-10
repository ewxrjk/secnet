source test-common.tcl

proc mss-program {} {
    global env
    set l ./make-secnet-sites
    if {![catch { set py $env(MTEST_PYTHON) }]} {
	set l [concat $py $l]
    }
    return $l
}

proc run-mss-userv {user group args} {
    eval [list prexec env USERV_USER=$user USERV_GROUP=$group] \
	 [mss-program] \
	 $args
}

proc run-mss {args} { eval [list prexec] [mss-program] $args }

proc diff {a b seddery {sedderyb X}} {
    if {![string compare $sedderyb X]} { set sedderyb $seddery }
    puts "$a $b $seddery $sedderyb"
    exec bash -c "
    	diff -u <( <$a $seddery  ) \\
        	<( <$b $sedderyb )
    "
}

proc diff-output {expected got suffix} {
    global seddery
    global tmp
    diff mtest/$expected$suffix $tmp/$got$suffix $seddery
}

proc diff-mss-sites-conf {expected got} {
    set seddery { sed -n 's/^[ \t]*//; /^[^#]/p' }
    diff $expected $got $seddery
}

file mkdir $tmp/groupfiles

set env(PYTHONHASHSEED) 0
set env(PYTHONBYTECODEBASE) 0

set seddery { sed -n 's/^[ \t]*//; /^[^#]/p' }

prefix_some_path PYTHONPATH .
