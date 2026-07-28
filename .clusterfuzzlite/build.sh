#!/bin/bash -eu

cd "$SRC/blobdive"
cargo fuzz build -O --debug-assertions

fuzz_output="fuzz/target/x86_64-unknown-linux-gnu/release"
for source in fuzz/fuzz_targets/*.rs; do
    target="$(basename "${source%.*}")"
    cp "$fuzz_output/$target" "$OUT/$target"
done

zip -q -j "$OUT/artifact_input_seed_corpus.zip" fuzz/seeds/*
