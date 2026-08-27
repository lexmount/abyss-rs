#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS CA black-box test only runs on macOS." >&2
  exit 2
fi

command -v cargo >/dev/null || {
  echo "cargo is required for the macOS CA black-box test." >&2
  exit 2
}
command -v openssl >/dev/null || {
  echo "openssl is required to generate temporary CA material." >&2
  exit 2
}
command -v security >/dev/null || {
  echo "security is required to manage macOS Keychain trust." >&2
  exit 2
}

RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
TMP_DIR="${ABYSS_MACOS_CA_BLACKBOX_TMP_DIR:-$(mktemp -d -t abyss-macos-ca-blackbox.XXXXXX)}"
CA_DIR="${TMP_DIR}/ca"
OPENSSL_CONFIG="${TMP_DIR}/openssl.cnf"

cleanup() {
  if [[ -z "${ABYSS_MACOS_CA_BLACKBOX_TMP_DIR:-}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

mkdir -p "${CA_DIR}"
cat >"${OPENSSL_CONFIG}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Abyss macOS CA Blackbox ${RUN_ID}

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

openssl req \
  -x509 \
  -newkey rsa:2048 \
  -nodes \
  -days 1 \
  -sha256 \
  -config "${OPENSSL_CONFIG}" \
  -keyout "${CA_DIR}/abyss-root-ca-key.pem" \
  -out "${CA_DIR}/abyss-root-ca.pem" >/dev/null 2>&1
openssl x509 \
  -in "${CA_DIR}/abyss-root-ca.pem" \
  -outform DER \
  -out "${CA_DIR}/abyss-root-ca.der"

ABYSS_MACOS_CA_BLACKBOX_APPLY=1 \
ABYSS_MACOS_CA_BLACKBOX_CA_DIR="${CA_DIR}" \
  cargo test -p abyss-mitm --test macos_ca_trust_store -- --ignored --nocapture

echo "blackbox: ok (macOS current-user Keychain CA round trip, run ${RUN_ID})"
