#!/bin/sh

# This script does a (remote) attestation of a TPM 2.0. To run it you need:
#
# - a TPM 2.0 (check that you have a /dev/tpmX device),
# - the Intel TPM 2.0 tools,
# - Python3 and its ECDSA library and
# - the verify.py script.
#
# On Debian Buster you can get everything via APT:
#
# > apt install tpm2-tools python3-ecdsa
#
# In order to get a signed list of PCR values we need to generate a key inside
# the TPM to sign them, called the Attestation Key (AK). In a production
# environment we would do an authenticated key exchange by using
# TPM2_ActivateCredential. Here we will directly generate the key.

# Before we can create an AK we need to load the Endorsement Key (EK). The EK
# is the unique, secure identity of the TPM and by extension the platform.

EK=$(mktemp)
tpm2_createek -c "$EK"

# Now we generate the AK, referencing the EK. We use tpm2_readpublic to get the
# public part of the AK. We will later use that to verify the signature.

AK=$(mktemp)
tpm2_createak -G ecc -C "$EK" -c "$AK" -p str:securepassword
PUBKEY=$(tpm2_readpublic -c "$AK" | sed -ne 's/^\(x\|y\): \([[:alnum:]]\+\)/\2/p' | awk '{print}' ORS='')

# We can now request a Quote i.e. a signature over all PCR values.

QUOTE=$(mktemp)
SIG=$(mktemp)
PCRS=$(mktemp)

tpm2_quote -c "$AK" -l sha256:all -p str:securepassword -o "$PCRS" -s "$SIG" -m "$QUOTE" -f tss

# After that we can verify the signed quote using the verify.py script

python3 verify.py "$PUBKEY" "$QUOTE" "$SIG"

# Cleanup 
rm "$QUOTE" "$EK" "$AK" "$SIG" "$PCRS"
