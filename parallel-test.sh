#!/bin/sh

# This file is part of secnet.
# See LICENCE and this file CREDITS for full list of copyright holders.
# SPDX-License-Identifier: GPL-3.0-or-later
# There is NO WARRANTY.

# usage
#  ../parallel-bisect.sh
#
# There should be subdirectories d.N for N=1..20
# which are build trees of the current secnet.

set -ex
cd d.1
make -j4 clean
make -j4 stest/d-nonnego-oo/ok
cd ..
for f in d.*; do
    ln d.1/secnet $f/secnet.new
    rm $f/secnet
    mv $f/secnet.new $f/secnet
done
here=$(git rev-parse HEAD)
us=${0%/*}
log=$us/at-$here.log
>$log
for x in `seq 1 ${1-500}`; do
    echo $x
    echo >>$log $x
    make -j -f $us/parallel-test.make >$us/dump/at-$here.log 2>&1
    echo >>$log "$x ok"
done
echo ok
