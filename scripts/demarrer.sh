#!/bin/sh
# Start the immune black box on the QNX target. Run as root from the directory holding the binaries.
# First run: provisions keys and learns the self. Re-runs keep both.
D=${D:-/data/antitout}
mkdir -p $D/cles
[ -f $D/cles/mldsa65.sec ] || ./bn_keys $D/cles
# The self: our own binaries only. intrus is deliberately left out.
[ -f $D/soi.conf ] || ./bn_soi $PWD/boitenoire $PWD/doseur $PWD/antitout $PWD/bn_verify > $D/soi.conf
./boitenoire $D/journal.bn $D/cles $D/soi.conf &
sleep 1
./antitout $D/soi.conf $D/memoire.conf &
sleep 1
./doseur &
echo "running. status:  cat /dev/boitenoire"
echo "verify:           ./bn_verify $D/journal.bn $D/cles"
