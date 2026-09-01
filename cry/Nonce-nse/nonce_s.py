import hashlib
from Crypto.Cipher import AES

# Private key (d) yang berhasil dipulihkan melalui serangan Lattice (HNP)
d = 79295886621100799536660173890999070263994144161520202567633589011913622152463

flag_enc = {
    "nonce": "da6eaa77b8d7943554928d2a69436d7a",
    "ciphertext": "76806de435f5e567db6d69eece732903dc249651dfc3a472921ef5926b9a1fd92804b2fe24d30aa45053defa4cc0cc3448c69127",
    "tag": "9b9819540d44cb41ba715412e6a6baf8",
}

DOMAIN = b"aethernet-vault::v2::attestation::(d)"
KDF_SALT = hashlib.sha256(b"aethernet-vault::stage::standalone").digest()
KDF_INFO = b"aethernet-vault|flag|aes256gcm"

def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > 64: key = hashlib.sha256(key).digest()
    key = key.ljust(64, b"\x00")
    return hashlib.sha256(bytes(b ^ 0x5C for b in key) + hashlib.sha256(bytes(b ^ 0x36 for b in key) + msg).digest()).digest()

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if salt == b"": salt = b"\x00" * 32
    prk = _hmac_sha256(salt, ikm)
    okm, t, c = b"", b"", 1
    while len(okm) < length:
        t = _hmac_sha256(prk, t + info + bytes([c]))
        okm += t
        c += 1
    return okm[:length]

def derive_key(d_val: int) -> bytes:
    ikm = hashlib.sha256(DOMAIN + d_val.to_bytes(32, "big")).digest()
    return hkdf_sha256(ikm, KDF_SALT, KDF_INFO, 32)

# Dekripsi Flag
key = derive_key(d)
cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(flag_enc["nonce"]))
flag = cipher.decrypt_and_verify(bytes.fromhex(flag_enc["ciphertext"]), bytes.fromhex(flag_enc["tag"]))

print(f"[!] FLAG: {flag.decode('utf-8')}")