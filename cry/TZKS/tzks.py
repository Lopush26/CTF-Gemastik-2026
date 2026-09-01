#!/usr/bin/env python3

import socket
import json
import hashlib
import itertools
import sys

HOST = "15.232.64.175"
PORT = 13500

SECRETS_FILE = "recovered_secrets.json"


# ============================================================
# Network
# ============================================================

def recv_json(sock):
    data = b""

    while b"\n" not in data:
        chunk = sock.recv(65536)

        if not chunk:
            raise EOFError("server closed connection")

        data += chunk

    line, _, _ = data.partition(b"\n")
    return json.loads(line.decode())


def send_json(sock, obj):
    msg = json.dumps(
        obj,
        separators=(",", ":")
    ) + "\n"

    sock.sendall(msg.encode())


# ============================================================
# PoW
# ============================================================

def solve_pow(chal, bits):
    target = 1 << (256 - bits)

    for i in itertools.count():
        s = str(i)

        digest = hashlib.sha256(
            (chal + s).encode()
        ).digest()

        if int.from_bytes(digest, "big") < target:
            return s

        if i % 1_000_000 == 0:
            print(f"[*] PoW tried {i}")


# ============================================================
# Ring
#
# Rq = Z_q[x] / (x^n + 1)
# ============================================================

def decode_ring(h, n, q):
    if not isinstance(h, str):
        raise TypeError("ring element must be a string")

    expected = n * 6

    # Normal representation.
    if len(h) == expected:
        padded = h

    # Server may omit the highest zero coefficient.
    elif len(h) < expected and len(h) % 6 == 0:
        missing = expected - len(h)

        print(
            f"[!] Ring element shortened: "
            f"{len(h)} -> {expected} hex chars; "
            f"padding {missing // 6} zero coefficient(s)"
        )

        padded = h + ("00" * missing)

    else:
        raise ValueError(
            f"invalid ring length: "
            f"{len(h)} != {expected}"
        )

    return [
        int(padded[i:i + 6], 16) % q
        for i in range(0, len(padded), 6)
    ]


def encode_ring(a, n, q):
    return "".join(
        f"{x % q:06x}"
        for x in a
    )


def ring_mul(a, b, q):
    n = len(a)
    out = [0] * n

    for i, ai in enumerate(a):
        if ai == 0:
            continue

        for j, bj in enumerate(b):
            if bj == 0:
                continue

            idx = i + j
            value = ai * bj

            if idx >= n:
                # x^n = -1
                out[idx - n] -= value
            else:
                out[idx] += value

    return [
        x % q
        for x in out
    ]


def scalar_mul_vec(c, vec, n, q):
    c = decode_ring(c, n, q)

    result = []

    for x in vec:
        x = decode_ring(x, n, q)

        result.append(
            encode_ring(
                ring_mul(c, x, q),
                n,
                q
            )
        )

    return result


def neg_vec(vec, n, q):
    result = []

    for x in vec:
        coeffs = decode_ring(x, n, q)

        result.append(
            encode_ring(
                [(-v) % q for v in coeffs],
                n,
                q
            )
        )

    return result


def zero_vec(k, n):
    return [
        "00" * (3 * n)
        for _ in range(k)
    ]


# ============================================================
# Load recovered secrets
# ============================================================

def load_secrets():
    with open(SECRETS_FILE) as f:
        data = json.load(f)

    required = [
        "n",
        "q",
        "k",
        "s",
        "e",
    ]

    for key in required:
        if key not in data:
            raise ValueError(
                f"missing field in "
                f"{SECRETS_FILE}: {key}"
            )

    return data


# ============================================================
# Main
# ============================================================

def main():

    # --------------------------------------------------------
    # Load recovered s and e
    # --------------------------------------------------------

    secrets = load_secrets()

    secret_n = secrets["n"]
    secret_q = secrets["q"]
    secret_k = secrets["k"]

    s = secrets["s"]
    e = secrets["e"]

    print("[+] Loaded recovered secrets")
    print(f"[+] secret n = {secret_n}")
    print(f"[+] secret q = {secret_q}")
    print(f"[+] secret k = {secret_k}")

    # --------------------------------------------------------
    # Connect
    # --------------------------------------------------------

    print()
    print(
        f"[*] Connecting to "
        f"{HOST}:{PORT}"
    )

    sock = socket.create_connection(
        (HOST, PORT)
    )

    # --------------------------------------------------------
    # PoW
    # --------------------------------------------------------

    hello = recv_json(sock)

    if "pow" not in hello:
        raise RuntimeError(
            f"unexpected first response: {hello}"
        )

    p = hello["pow"]

    chal = p["chal"]
    bits = p["bits"]

    print(f"[+] chal = {chal}")
    print(f"[+] bits = {bits}")

    solution = solve_pow(
        chal,
        bits
    )

    print(f"[+] PoW = {solution}")

    send_json(sock, {
        "pow": solution
    })

    # --------------------------------------------------------
    # Public parameters
    # --------------------------------------------------------

    params = recv_json(sock)

    n = params["n"]
    q = params["q"]
    k = params["k"]

    print(f"[+] n = {n}")
    print(f"[+] q = {q}")
    print(f"[+] k = {k}")
    print(f"[+] gamma = {params['gamma']}")
    print(f"[+] tau = {params['tau']}")

    # --------------------------------------------------------
    # Check recovered secrets belong to this parameter set.
    # --------------------------------------------------------

    if n != secret_n:
        raise RuntimeError(
            f"n mismatch: "
            f"current={n}, secrets={secret_n}"
        )

    if q != secret_q:
        raise RuntimeError(
            f"q mismatch: "
            f"current={q}, secrets={secret_q}"
        )

    if k != secret_k:
        raise RuntimeError(
            f"k mismatch: "
            f"current={k}, secrets={secret_k}"
        )

    # --------------------------------------------------------
    # Enrollment bypass
    # --------------------------------------------------------

    print()
    print("[*] === ENROLL ===")

    send_json(sock, {
        "cmd": "enroll"
    })

    response = recv_json(sock)

    if "c0" not in response:
        raise RuntimeError(
            f"enroll failed: {response}"
        )

    C0 = response["c0"]

    print("[+] C0 received")

    C0T = scalar_mul_vec(
        C0,
        params["t"],
        n,
        q
    )

    W0 = neg_vec(
        C0T,
        n,
        q
    )

    send_json(sock, {
        "cmd": "enroll_open",
        "w": W0,
        "z1": zero_vec(k, n),
        "z2": zero_vec(k, n)
    })

    response = recv_json(sock)

    print(
        "[+] enroll_open:",
        response
    )

    if response.get("ok") is not True:
        raise RuntimeError(
            "enrollment forgery failed"
        )

    print(
        "[+] Authorization established"
    )

    # --------------------------------------------------------
    # AUTH
    # --------------------------------------------------------

    print()
    print("[*] === AUTH FORGERY ===")

    W = zero_vec(
        k,
        n
    )

    send_json(sock, {
        "cmd": "auth",
        "w": W
    })

    response = recv_json(sock)

    if "c" not in response:
        raise RuntimeError(
            f"auth failed: {response}"
        )

    C = response["c"]

    print(
        "[+] challenge length =",
        len(C)
    )

    # --------------------------------------------------------
    # z1 = C*s
    # z2 = C*e
    # --------------------------------------------------------

    print("[*] Computing z1 = C*s")

    z1 = scalar_mul_vec(
        C,
        s,
        n,
        q
    )

    print("[+] z1 computed")

    print("[*] Computing z2 = C*e")

    z2 = scalar_mul_vec(
        C,
        e,
        n,
        q
    )

    print("[+] z2 computed")

    # --------------------------------------------------------
    # Send forged response
    # --------------------------------------------------------

    print()
    print("[*] Sending auth_resp")

    send_json(sock, {
        "cmd": "auth_resp",
        "z1": z1,
        "z2": z2
    })

    # --------------------------------------------------------
    # Final
    # --------------------------------------------------------

    while True:

        data = sock.recv(65536)

        if not data:
            break

        text = data.decode(
            errors="replace"
        )

        print(text, end="")

        if "GEMASTIK19{" in text:
            print()
            print("[+] FLAG FOUND")
            break


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)

    except Exception as exc:
        print(
            f"[!] Fatal error: {exc}"
        )
        sys.exit(1)