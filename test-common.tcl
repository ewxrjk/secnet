
if {![catch {
    set builddir $env(STEST_BUILDDIR)
}]} {} else {
    set builddir .
}

if {![catch {
    set tmp $env(AUTOPKGTEST_ARTIACTS)
}]} {} elseif {![catch {
    set tmp $env(AUTOPKGTEST_TMP)
}]} {} elseif {[regsub {^stest/t-} $argv0 {stest/d-} tmp]} {
    set tmp $builddir/$tmp
    file mkdir $tmp
}
