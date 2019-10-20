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
    eval [list exec env USERV_USER=$user USERV_GROUP=$group] \
	 [mss-program] \
	 $args
}

proc run-mss {args} { eval [list exec] [mss-program] $args }

proc diff-output {expected got suffix} {
    global seddery
    global tmp
    exec bash -c "
    	diff -u <($seddery mtest/$expected$suffix) \\
        	<($seddery $tmp/$got$suffix      )
    "
}

file mkdir $tmp/groupfiles

set env(PYTHONHASHSEED) 0
set env(PYTHONBYTECODEBASE) 0

set seddery { sed -n 's/^[ \t]*//; /^[^#]/p' }

prefix_some_path PYTHONPATH .
