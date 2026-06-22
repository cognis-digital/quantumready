"""token_service.py — issues and verifies signed service tokens.

Excerpt from a microservice that mints short-lived auth tokens. Up for review
before the team commits to a post-quantum signature roadmap.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes


def new_signing_key():
    # RSA-2048 signing key for the token issuer.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def new_session_kex_key():
    # ECDH on P-256 for the per-session ephemeral key agreement.
    return ec.generate_private_key(ec.SECP256R1())


def sign_token(key, payload: bytes) -> bytes:
    # ECDSA fallback path uses prime256v1.
    return key.sign(payload, ec.ECDSA(hashes.SHA256()))
