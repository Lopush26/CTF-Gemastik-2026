import base64
import hashlib

install_key = base64.b64decode(
    "zFQ9GVudkfiHhytpG1zAl2B+DHLhE650mzYFCL+pqSI="
)

salt = base64.b64decode(
    "5n581xQBvjFW5FFDwj2stw=="
)

key = hashlib.pbkdf2_hmac(
    "sha256",
    install_key,
    salt,
    120000,
    32
)

print(key.hex())
