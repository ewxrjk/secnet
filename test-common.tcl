# This file is part of secnet.
# See LICENCE and this file CREDITS for full list of copyright holders.
# SPDX-License-Identifier: GPL-3.0-or-later
# There is NO WARRANTY.

proc prefix_some_path {pathvar entry} {
    global env
    set l {}
    catch { set l [split $env($pathvar) :] }
    set l [concat [list $entry] $l]
    set env($pathvar) [join $l :]
}

proc prexec {args} {
    puts "exec $args"
    eval exec $args
}

if {![catch {
    set builddir $env(SECNET_TEST_BUILDDIR)
}]} {} else {
    set builddir .
}

if {![catch {
    set tmp $env(AUTOPKGTEST_ARTIACTS)
}]} {} elseif {![catch {
    set tmp $env(AUTOPKGTEST_TMP)
}]} {} elseif {[regsub {^(?:\./)?([sm]test)/t-} $argv0 {\1/d-} tmp]} {
    set tmp $builddir/$tmp
    file mkdir $tmp
}
