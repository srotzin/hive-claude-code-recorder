#!/usr/bin/env bash
# Rebuilds the circuits and their PLONK keys from source and the public setup file, and checks the
# verification keys against the ones committed in keys/. PLONK needs no setup ceremony of its own:
# the keys follow from the circuit and the public Perpetual Powers of Tau file, so anyone gets the same bytes.
#   needs: circom 2.2.2 on PATH, node 20+, npm
set -euo pipefail
cd "$(dirname "$0")"
PTAU=ppot_0080_14.ptau
PTAU_URL=https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_14.ptau
PTAU_SHA256=3ca1149e9349b22b0ee0649399cfb787677129b7b1189d1899fc0d615d9583db
[ -d node_modules/snarkjs ] || npm install --no-audit --no-fund
mkdir -p build
[ -f build/$PTAU ] || curl -sL -o build/$PTAU $PTAU_URL
echo "$PTAU_SHA256  build/$PTAU" | sha256sum -c -
for c in spread spread-equal-weight; do
  circom circuits/$c.circom --r1cs --wasm -o build >/dev/null
  npx snarkjs plonk setup build/$c.r1cs build/$PTAU build/$c.zkey >/dev/null
  npx snarkjs zkey export verificationkey build/$c.zkey build/$c.vkey.json >/dev/null
  node -e 'const fs=require("fs"),a=JSON.parse(fs.readFileSync(process.argv[1])),b=JSON.parse(fs.readFileSync(process.argv[2]));if(JSON.stringify(a)!==JSON.stringify(b)){console.error("MISMATCH",process.argv[1]);process.exit(1)}console.log("same verification key:",process.argv[2])' build/$c.vkey.json keys/$c.vkey.json
done
