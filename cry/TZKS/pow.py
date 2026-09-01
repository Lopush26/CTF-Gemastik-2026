import hashlib

chal = "8f8789be362af157ea836a93c0777cc6"

i = 0

while True:
    s = str(i)

    digest = hashlib.sha256(
        (chal + s).encode()
    ).digest()

    if int.from_bytes(digest, "big") < (1 << (256 - 20)):
        print("[+] PoW:", s)
        print("[+] SHA256:", digest.hex())
        break

    i += 1