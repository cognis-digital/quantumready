"""Sample service that relies on quantum-vulnerable cryptography.

Used by demo 11 to show feed enrichment (CISA-KEV + NVD) over a real crypto
inventory. This is illustrative input for the scanner — not a real service.
"""
import rsa  # noqa: F401


def issue_session_key():
    # RSA key generation — broken by Shor's algorithm on a CRQC.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


# Elliptic-curve material (ECDSA / secp256k1) — also Shor-vulnerable.
SIGNING_CURVE = "secp256k1"   # ECDSA
PEER_CURVE = "prime256v1"     # P-256

# Classical key establishment: finite-field Diffie-Hellman (IKE-style).
KEX = "diffie-hellman-group14-sha256"

# Classical TLS key-exchange suite (no PQC hybrid).
TLS_CIPHER = "TLS_RSA_WITH_AES_256_GCM_SHA384"
