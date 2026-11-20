#!/bin/bash
# Build liboqs and antiTOUT for QNX 8.0. Run inside the qnx-build container (or any Linux x86_64 host
# with QNX SDP 8.0 + host tools). Usage: scripts/construire-qnx.sh [x86_64|aarch64]
set -euo pipefail
ARCH=${1:-x86_64}
HERE=$(cd "$(dirname "$0")/.." && pwd)
OQS_SRC=${OQS_SRC:-$HERE/../tiers/liboqs}
OUT=$HERE/../tiers/oqs-qnx-$ARCH
source "${QNX_SDP:-$HOME/qnx800}/qnxsdp-env.sh"
cmake -S "$OQS_SRC" -B "$OQS_SRC/build-qnx-$ARCH" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$HERE/cmake/qnx-$ARCH.cmake" -DCMAKE_BUILD_TYPE=Release \
  -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;SIG_slh_dsa_pure_sha2_128s" -DCMAKE_INSTALL_PREFIX="$OUT"
# Under Rosetta, the compiler sometimes crashes at random; a rerun resumes where it stopped.
retry() { for i in 1 2 3 4 5; do "$@" && return 0; echo "retry $i after a compiler crash"; done; return 1; }
retry ninja -k 0 -C "$OQS_SRC/build-qnx-$ARCH" install
cmake -S "$HERE" -B "$HERE/build-qnx-$ARCH" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$HERE/cmake/qnx-$ARCH.cmake" -DCMAKE_BUILD_TYPE=Release -DOQS_PREFIX="$OUT"
retry ninja -k 0 -C "$HERE/build-qnx-$ARCH"
ls -la "$HERE/build-qnx-$ARCH" | grep -E "boitenoire|doseur|antitout|intrus|bn_"
