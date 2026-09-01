import base64
import hashlib
import struct
from pathlib import Path
from Crypto.Cipher import AES


BASE = Path(__file__).parent

WAL = (
    BASE
    / "soal"
    / "com.example.cinder"
    / "databases"
    / "chat.db-wal"
)


# ============================================================
# KEY
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

print("[+] AES key:", key.hex())
print("[+] WAL:", WAL)

data = WAL.read_bytes()

print("[+] WAL size:", len(data))


# ============================================================
# VARINT
# ============================================================

def varint(buf, pos):
    value = 0

    for i in range(9):
        b = buf[pos + i]

        if i == 8:
            value = (value << 8) | b
            return value, pos + 9

        value = (value << 7) | (b & 0x7f)

        if not (b & 0x80):
            return value, pos + i + 1

    raise ValueError("invalid varint")


# ============================================================
# SQLite WAL
# ============================================================

PAGE_SIZE = 512
WAL_HEADER = 32
FRAME_SIZE = 24 + PAGE_SIZE

frames = []

for off in range(WAL_HEADER, len(data), FRAME_SIZE):

    if off + FRAME_SIZE > len(data):
        break

    frame_header = data[off:off + 24]

    page_no = struct.unpack(">I", frame_header[0:4])[0]
    db_size = struct.unpack(">I", frame_header[4:8])[0]

    page = data[off + 24:off + 24 + PAGE_SIZE]

    frames.append((off, page_no, page))

print("[+] WAL frames:", len(frames))


# ============================================================
# SQLite table-leaf parser
# ============================================================

def parse_table_leaf(page, page_number):

    # page 1 has 100-byte database header.
    # WAL pages >= 2 have normal SQLite page header.
    hdr = 0

    page_type = page[hdr]

    # 0x0d = table leaf
    if page_type != 0x0d:
        return []

    cell_count = int.from_bytes(
        page[hdr + 3:hdr + 5],
        "big"
    )

    results = []

    for n in range(cell_count):

        ptr_pos = hdr + 8 + (n * 2)

        if ptr_pos + 2 > len(page):
            continue

        cell_offset = int.from_bytes(
            page[ptr_pos:ptr_pos + 2],
            "big"
        )

        if cell_offset >= len(page):
            continue

        try:
            payload_len, p = varint(page, cell_offset)

            rowid, p = varint(page, p)

            payload = page[p:p + payload_len]

            if len(payload) != payload_len:
                continue

            results.append(
                (
                    rowid,
                    payload,
                    cell_offset
                )
            )

        except Exception:
            continue

    return results


# ============================================================
# SQLite record decoder
# ============================================================

def decode_record(payload):

    try:
        header_size, p = varint(payload, 0)

        serials = []

        while p < header_size:
            value, p = varint(payload, p)
            serials.append(value)

        body_pos = header_size

        fields = []

        for serial in serials:

            if serial == 0:
                size = 0

            elif serial == 1:
                size = 1

            elif serial == 2:
                size = 2

            elif serial == 3:
                size = 3

            elif serial == 4:
                size = 4

            elif serial == 5:
                size = 6

            elif serial == 6:
                size = 8

            elif serial == 7:
                size = 8

            elif serial >= 12:

                if serial % 2 == 0:
                    size = (serial - 12) // 2
                else:
                    size = (serial - 13) // 2

            else:
                return None

            raw = payload[body_pos:body_pos + size]

            if len(raw) != size:
                return None

            fields.append((serial, raw))

            body_pos += size

        return fields

    except Exception:
        return None


# ============================================================
# Protobuf decoder untuk body
# ============================================================

def parse_message_blob(blob):

    result = {}

    pos = 0

    while pos < len(blob):

        key, pos = varint(blob, pos)

        field = key >> 3
        wire = key & 7

        if wire != 2:
            break

        length, pos = varint(blob, pos)

        value = blob[pos:pos + length]

        if len(value) != length:
            break

        pos += length

        result[field] = value

    return result


# ============================================================
# Cari ROWID 12
# ============================================================

print()
print("=" * 70)
print("[+] SEARCHING SQLITE ROWID 12")
print("=" * 70)

found = 0

for frame_off, page_no, page in frames:

    rows = parse_table_leaf(page, page_no)

    for rowid, payload, cell_offset in rows:

        if rowid != 12:
            continue

        found += 1

        print()
        print("[+] ROWID 12 FOUND")
        print("    WAL offset :", hex(frame_off))
        print("    page       :", page_no)
        print("    cell       :", hex(cell_offset))
        print("    payload    :", len(payload), "bytes")
        print("    payload hex:", payload.hex())

        record = decode_record(payload)

        if not record:
            print("[-] Gagal decode SQLite record")
            continue

        print()
        print("[+] SQLite fields:")

        for i, (serial, raw) in enumerate(record):

            print(
                f"    field {i}: "
                f"serial={serial} "
                f"len={len(raw)} "
                f"hex={raw.hex()}"
            )

        # messages schema:
        #
        # id INTEGER PRIMARY KEY
        # thread TEXT
        # ts INTEGER
        # body BLOB
        # state INTEGER
        #
        # Karena id adalah rowid, payload biasanya:
        # thread, ts, body, state

        if len(record) < 4:
            continue


        thread_raw = record[0][1]
        ts_raw = record[1][1]
        body = record[2][1]

        thread = thread_raw.decode(
            "utf-8",
            errors="replace"
        )

        print()
        print("[+] thread:", thread)
        print("[+] body length:", len(body))
        print("[+] body hex:", body.hex())

        # ----------------------------------------------------
        # protobuf
        # ----------------------------------------------------

        proto = parse_message_blob(body)

        print()
        print("[+] protobuf fields:")

        for field, value in proto.items():

            print(
                f"    field {field}: "
                f"{value.hex()}"
            )

        # field 1 = sender
        # field 2 = nonce
        # field 3 = ciphertext
        # field 4 = tag

        sender = proto.get(1)
        nonce = proto.get(2)
        ciphertext = proto.get(3)
        tag = proto.get(4)

        if not all(
            x is not None
            for x in (sender, nonce, ciphertext, tag)
        ):
            print("[-] Struktur protobuf tidak lengkap")
            continue

        print()
        print("[+] sender:", sender.decode(
            "utf-8",
            errors="replace"
        ))

        print("[+] nonce :", nonce.hex())
        print("[+] ct    :", ciphertext.hex())
        print("[+] tag   :", tag.hex())

        # ----------------------------------------------------
        # AES-GCM
        # ----------------------------------------------------

        aad = f"{thread}:12".encode()

        print("[+] AAD   :", aad.decode())

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

            print()
            print("=" * 70)
            print("[+] SUCCESS - MESSAGE ID 12")
            print("=" * 70)
            print()
            print(plaintext.decode(
                "utf-8",
                errors="replace"
            ))
            print()
            print("=" * 70)

        except Exception as e:

            print()
            print("[-] AES-GCM gagal:", e)


print()
print("[+] Total ROWID 12:", found)