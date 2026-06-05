#!/bin/bash
# =============================================================================
# generate_certs.sh — OpenSSL Self-Signed Certificate Generation
# =============================================================================
# SECURITY CONCEPT: Identity Verification & Confidentiality via PKI
#
# This script generates a 2048-bit RSA private key and a self-signed X.509
# certificate valid for 365 days.  In production, this certificate would be
# signed by a trusted Certificate Authority (CA).  For this lab demonstration
# a self-signed cert is sufficient to enable and test TLS encryption.
#
# Files produced:
#   server.key  — RSA private key  (keep SECRET; used to decrypt sessions)
#   server.crt  — X.509 certificate (shared with clients during TLS handshake)
#
# Usage: bash generate_certs.sh
# =============================================================================

set -e   # Exit immediately on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_FILE="${SCRIPT_DIR}/server.key"
CERT_FILE="${SCRIPT_DIR}/server.crt"
DAYS_VALID=365
KEY_BITS=2048

echo "============================================================"
echo "  MODULE A — OpenSSL Certificate Generation"
echo "============================================================"

# Check that openssl is installed
if ! command -v openssl &>/dev/null; then
    echo "  [ERROR] openssl is not installed."
    echo "          Install it with:  sudo apt-get install openssl"
    exit 1
fi

echo "  Generating ${KEY_BITS}-bit RSA private key..."
echo "  Output:  ${KEY_FILE}"
echo "  Output:  ${CERT_FILE}"
echo ""

# Step 1: Generate private key + self-signed certificate in a single command.
#   -x509       : Output a self-signed certificate instead of a CSR
#   -newkey     : Generate a new RSA key of the specified size
#   -nodes      : No DES encryption on the private key (no passphrase needed
#                 for automated server startup)
#   -days       : Validity period
#   -subj       : Non-interactive subject fields (avoids interactive prompts)
#   -keyout     : Where to write the private key
#   -out        : Where to write the certificate

openssl req -x509 \
    -newkey rsa:${KEY_BITS} \
    -nodes \
    -days ${DAYS_VALID} \
    -subj "/C=PK/ST=Punjab/L=Lahore/O=IS-Lab-Demo/OU=Security/CN=localhost" \
    -keyout "${KEY_FILE}" \
    -out    "${CERT_FILE}"

echo ""
echo "  ✔  Certificate generated successfully!"
echo ""
echo "  Key  : ${KEY_FILE}"
echo "  Cert : ${CERT_FILE}"
echo ""

# Display certificate details for lab report / verification
echo "------------------------------------------------------------"
echo "  Certificate Details:"
echo "------------------------------------------------------------"
openssl x509 -in "${CERT_FILE}" -text -noout | grep -E \
    "Subject:|Issuer:|Not Before:|Not After:|Public-Key:"

echo ""
echo "============================================================"
echo "  You can now start the secure server:"
echo "    python3 secure_server.py"
echo "============================================================"
