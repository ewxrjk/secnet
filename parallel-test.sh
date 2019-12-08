#!/bin/sh

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
for x in `seq 1 500`; do
    echo $x
    make -j -f ${0%/*}/parallel-test.make
done
echo ok
