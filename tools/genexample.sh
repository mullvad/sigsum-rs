#!/bin/bash

# Regenerates the variables for the example in the lib.rs (and the README).

set -eux

tmpdir=$(mktemp -d)
trap 'rm -rf $tmpdir' EXIT

# We use a throaway key so we don't have a gazillion security scanners spamming
# us about commiting an OpenSSH private key.
keyfile="$tmpdir/signer"
ssh-keygen -t ed25519 -N "" -f "$keyfile"

data="Hello, Sigsum!\n"
signer=$(go run sigsum.org/sigsum-go/cmd/sigsum-key@v0.14 to-hex -k "${keyfile}.pub")
signature=$(printf "$data" | go run sigsum.org/sigsum-go/cmd/sigsum-submit@v0.14 -k "$keyfile" -P sigsum-test-2025-3)

printf 'let data = b"%s";\n' "$data"
printf 'let signers: Vec<PublicKey> =\n    vec![hex!("%s").into()];\n' "$signer";
printf 'let signature = SigsumSignature::from_ascii("%s\n")?;\n' "$signature";
