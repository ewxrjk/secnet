source test-common.tcl

proc mss-program {} {
    set l ./make-secnet-sites
}

proc run-mss-userv {user group args} {
    eval [list exec env USERV_USER=$user USERV_GROUP=$group] \
	 [mss-program] \
	 $args
}

file mkdir $tmp/groupfiles

prefix_some_path PYTHONPATH .
