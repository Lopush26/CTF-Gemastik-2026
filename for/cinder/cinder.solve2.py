import base64
import hashlib
from pathlib import Path
from Crypto.Cipher import AES


# ============================================================
# 1. Lokasi WAL
# ============================================================

BASE = Path(__file__).parent

WAL = (
    BASE
    / "soal"
    / "com.example.cinder"
    / "databases"
    / "chat.db-wal"
)


# ============================================================
# 2. Derive AES-256 key
# ============================================================

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

print("[+] Key:", key.hex())
print("[+] WAL :", WAL)


if not WAL.exists():
    raise FileNotFoundError(
        f"WAL tidak ditemukan:\n{WAL}"
    )


data = WAL.read_bytes()

print("[+] WAL size:", len(data), "bytes")


# ============================================================
# 3. Varint parser
# ============================================================

def read_varint(data, pos):
    value = 0
    shift = 0

    while pos < len(data):
        b = data[pos]
        pos += 1

        value |= (b & 0x7f) << shift

        if not (b & 0x80):
            return value, pos

        shift += 7

    return None, pos


# ============================================================
# 4. Cari protobuf message
# ============================================================

aad = b"kurir:12"

found = 0

for i in range(len(data)):

    # field 1: sender
    if data[i] != 0x0a:
        continue

    try:
        sender_len, pos = read_varint(data, i + 1)

        if sender_len is None:
            continue

        if pos + sender_len > len(data):
            continue

        sender = data[pos:pos + sender_len]

        pos += sender_len

        # field 2: nonce
        if pos >= len(data) or data[pos] != 0x12:
            continue

        nonce_len, pos = read_varint(data, pos + 1)

        if nonce_len != 12:
            continue

        if pos + 12 > len(data):
            continue

        nonce = data[pos:pos + 12]

        pos += 12

        # field 3: ciphertext
        if pos >= len(data) or data[pos] != 0x1a:
            continue

        ct_len, pos = read_varint(data, pos + 1)

        if ct_len is None:
            continue

        if pos + ct_len > len(data):
            continue

        ciphertext = data[pos:pos + ct_len]

        pos += ct_len

        # field 4: GCM tag
        if pos >= len(data) or data[pos] != 0x22:
            continue

        tag_len, pos = read_varint(data, pos + 1)

        if tag_len != 16:
            continue

        if pos + 16 > len(data):
            continue

        tag = data[pos:pos + 16]

        # ====================================================
        # 5. Coba decrypt dengan AAD kurir:12
        # ====================================================

        try:
            cipher = AES.new(
                key,
                AES.MODE_GCM,
                nonce=nonce
            )

            cipher.update(aad)

            plaintext = cipher.decrypt_and_verify(
                ciphertext,
                tag
            )

            found += 1

            print()
            print("=" * 70)
            print("[+] KURIR:12 BERHASIL DITEMUKAN")
            print("=" * 70)
            print("WAL offset :", hex(i))
            print("Sender     :", sender.decode(errors="replace"))
            print("Nonce      :", nonce.hex())
            print("Ciphertext :", ciphertext.hex())
            print("Tag        :", tag.hex())
            print()
            print("PLAINTEXT:")
            print(plaintext.decode(errors="replace"))
            print("=" * 70)

        except ValueError:
            pass

    except Exception:
        pass


print()
print("[+] Total kurir:12 ditemukan:", found)