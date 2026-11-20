#!/bin/sh
# The demo scenes, run on the QNX target as root from the binaries' directory after demarrer.sh.
D=${D:-/data/antitout}
J=$D/journal.bn
scene() { echo; echo "=================== $*"; }
# last journal lines of the given types (extended regex)
show()  { ./bn_list $J | grep -E "$1" | tail -${2:-3}; }

scene "1. Prescription within protocol: carboplatin 500 mg"
./intrus prescribe carboplatin 500; sleep 5; show "carboplatin target 500" 2

scene "2. Overdose x10: carboplatin 9000 mg (protocol maximum 900 mg)"
./intrus prescribe carboplatin 9000; sleep 1; show "DOSE_REFUSED" 1

scene "3. Foreign process at priority 45, above the dispensing loop (40)"
./intrus cpu 6 & sleep 7; show "QUARANTINE|EXPEL|INTRUDER" 2

scene "4. Relapse: it comes back and raises its priority again"
./intrus cpu-relapse 8 & sleep 9; show "QUARANTINE|EXPEL" 2

scene "5. Membrane: a foreign binary tries to write into the black box"
./intrus write; sleep 1; show "MEMBRANE_REFUSE|INTRUDER|QUARANTINE" 3

scene "Live journal"
./bn_verify $J $D/cles

scene "6. Rewrite history on a copy: hide the 500 mg dose as 5000 mg"
cp $J $D/copie.bn
SEQ=$(./bn_list $D/copie.bn | grep "DOSE_DELIVERED   carboplatin target 500" | head -1 | sed -E 's/^#([0-9]+).*/\1/')
./intrus forge $D/copie.bn $SEQ
./bn_list $D/copie.bn | grep "^#$SEQ "
./bn_verify $D/copie.bn $D/cles
