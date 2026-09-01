#!/usr/bin/env python3

import socket
import json
import hashlib
import itertools
import sys


HOST = "15.232.64.175"
PORT = 13500


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
# Rq = Z_q[x] / (x^n + 1)
# ============================================================

def decode_ring(h, n, q):
    if not isinstance(h, str):
        raise TypeError("ring element must be string")

    if len(h) != n * 6:
        raise ValueError(
            f"invalid ring length "
            f"{len(h)} != {n * 6}"
        )

    return [
        int(h[i:i + 6], 16) % q
        for i in range(0, len(h), 6)
    ]


# ============================================================
# Authorized session
# ============================================================

def connect_authorized():
    print("[*] Connecting")

    sock = socket.create_connection(
        (HOST, PORT)
    )

    # --------------------------------------------------------
    # PoW
    # --------------------------------------------------------

    hello = recv_json(sock)

    p = hello["pow"]

    solution = solve_pow(
        p["chal"],
        p["bits"]
    )

    print(f"[+] PoW = {solution}")

    send_json(sock, {
        "pow": solution
    })

    # --------------------------------------------------------
    # Parameters
    # --------------------------------------------------------

    params = recv_json(sock)

    n = params["n"]
    q = params["q"]
    k = params["k"]

    print(
        f"[+] n={n} "
        f"q={q} "
        f"k={k} "
        f"l={params['l']} "
        f"gamma={params['gamma']} "
        f"tau={params['tau']}"
    )

    # --------------------------------------------------------
    # Enrollment bypass
    # --------------------------------------------------------

    send_json(sock, {
        "cmd": "enroll"
    })

    response = recv_json(sock)

    if "c0" not in response:
        raise RuntimeError(
            f"enroll failed: {response}"
        )

    C0 = response["c0"]

    # We need C0*T.
    # This is only for the enrollment forgery.

    def ring_mul(a, b):
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
                    out[idx - n] -= value
                else:
                    out[idx] += value

        return [
            x % q
            for x in out
        ]

    c0_coeffs = decode_ring(
        C0,
        n,
        q
    )

    W0 = []

    for t in params["t"]:
        t_coeffs = decode_ring(
            t,
            n,
            q
        )

        product = ring_mul(
            c0_coeffs,
            t_coeffs
        )

        W0.append(
            "".join(
                f"{(-x) % q:06x}"
                for x in product
            )
        )

    zero = [
        "00" * (3 * n)
        for _ in range(k)
    ]

    send_json(sock, {
        "cmd": "enroll_open",
        "w": W0,
        "z1": zero,
        "z2": zero
    })

    response = recv_json(sock)

    if response.get("ok") is not True:
        raise RuntimeError(
            f"enroll_open failed: {response}"
        )

    print("[+] Authorization established")

    return sock, params


# ============================================================
# One prove query
# ============================================================

def prove(sock, label):
    send_json(sock, {
        "cmd": "prove",
        "label": label
    })

    response = recv_json(sock)

    if "error" in response:
        raise RuntimeError(
            f"prove({label}) failed: {response}"
        )

    for key in ["w", "c", "z", "a"]:
        if key not in response:
            raise RuntimeError(
                f"prove response missing {key}"
            )

    return response


# ============================================================
# Main
# ============================================================

def main():

    sock, params = connect_authorized()

    try:
        # ----------------------------------------------------
        # Same label multiple times
        # ----------------------------------------------------

        labels = [
            "0000",
            "0001",
            "0002",
            "0003",
            "0004",
            "0005",
        ]

        repetitions = 3

        samples = {}

        for label in labels:

            print()
            print(
                f"[*] === LABEL {label} "
                f"({repetitions} proofs) ==="
            )

            samples[label] = []

            for i in range(repetitions):

                print(
                    f"[*] prove {label} "
                    f"#{i + 1}"
                )

                proof = prove(
                    sock,
                    label
                )

                samples[label].append(
                    proof
                )

                print(
                    f"    w={len(proof['w'])} "
                    f"c={len(proof['c'])} "
                    f"z={len(proof['z'])} "
                    f"a={len(proof['a'])}"
                )

                # Compare with first transcript.
                if i > 0:

                    first = samples[label][0]

                    print(
                        "    w identical:",
                        proof["w"] == first["w"]
                    )

                    print(
                        "    a identical:",
                        proof["a"] == first["a"]
                    )

                    print(
                        "    c identical:",
                        proof["c"] == first["c"]
                    )

                    print(
                        "    z identical:",
                        proof["z"] == first["z"]
                    )

        # ----------------------------------------------------
        # Save transcripts
        # ----------------------------------------------------

        with open(
            "prove_samples.json",
            "w"
        ) as f:
            json.dump(
                samples,
                f,
                indent=2
            )

        print()
        print(
            "[+] Saved all transcripts "
            "to prove_samples.json"
        )

    finally:
        sock.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(1)
    except Exception as exc:
        print(
            "[!] Fatal error:",
            exc
        )
        sys.exit(1)