#!/bin/bash

set -e

scriptdir="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
repodir="$scriptdir/.."

echo "Executing from directory: $scriptdir"

print_usage() {
cat <<DONE
Usage: `basename $0` <prover_key_path> [<output_dir>]

Creates proofs for the inputs generated by the keyless-circuit's input_gen.py 
script. We use these proofs to test our Rust verifier.

Uses <prover_key_path> as the path to the prover key.

Proofs are stored in <output_dir> which defaults to the root of the repository (i.e., $repodir)
DONE
}

pushd() {
    command pushd "$@" > /dev/null
}

popd() {
    command popd "$@" > /dev/null
}

proofgen() {
    prover_key=$1
    outdir=$2
    
    if [ ! -f $prover_key ]; then
        echo "$prover_key is not a file (may be a directory?)"
        exit 1
    fi

    prover_key=`realpath $prover_key`

    echo
    echo "Using proving key from $prover_key"

    echo
    echo "Creating python3 virtual env w/ deps..."
    virtualenv ig
    source ./ig/bin/activate

    pip3 install pyjwt pycryptodome cryptography

    pushd templates/
    {
        echo
        echo "(Re)compiling circuit. This will take several seconds..."
        circom -l `npm root -g` main.circom --r1cs --wasm --sym
    }
    popd

    echo
    echo "Running input_gen.py..."
    touch input.json
    python3 tools/input_gen.py
    pushd templates/main_js
    {
        echo
        echo "Generating witness..."
        node generate_witness.js main.wasm ../../input.json witness.wtns
    }
    popd

    echo
    echo "Generating proof. Should take around 30 seconds..."
    rm -f $outdir/proof.json
    rm -f $outdir/public.json
    snarkjs groth16 prove $prover_key templates/main_js/witness.wtns $outdir/proof.json $outdir/public.json

    echo
    echo "Done. Find the {input,proof,public}.json output files in `pwd`"
}

if [ "$#" -lt 2 ]; then
    print_usage
    exit 1
fi

outdir=${3:-$repodir}
mkdir -p $outdir
pushd $repodir/
    proofgen "$1" "$2" "$outdir"
popd
