from quantumready.core import scan_text, readiness
def test_detects_rsa_ecc():
    f = scan_text("key = rsa.generate_private_key(2048)\nuse secp256k1 and ML-KEM")
    ids = {x.id for x in f}
    assert "QR-RSA" in ids and "QR-ECC" in ids and "QR-GOODKEM" in ids
    assert readiness(f)["grade"]
