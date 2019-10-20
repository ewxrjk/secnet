
proc prefix_some_path {pathvar entry} {
    global env
    set l {}
    catch { set l [split $env($pathvar) :] }
    set l [concat [list $entry] $l]
    set env($pathvar) [join $l :]
}

if {![catch {
    set builddir $env(STEST_BUILDDIR)
}]} {} else {
    set builddir .
}

if {![catch {
    set tmp $env(AUTOPKGTEST_ARTIACTS)
}]} {} elseif {![catch {
    set tmp $env(AUTOPKGTEST_TMP)
}]} {} elseif {[regsub {^([sm]test)/t-} $argv0 {\1/d-} tmp]} {
    set tmp $builddir/$tmp
    file mkdir $tmp
}
