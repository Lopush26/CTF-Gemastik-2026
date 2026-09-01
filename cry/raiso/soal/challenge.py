#!/usr/bin/env python3
import hashlib

P = 2147483647


def H(data: bytes) -> int:
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h[:8], "big") % P


def F(a: int, b: int, d: int) -> tuple:
    t = (d * H(str(a).encode() + b":" + str(b).encode() + b":" + str(d).encode())) % P
    return (b + t) % P, a


if __name__ == "__main__":
    import json

    with open("payload.json") as f:
        cfg = json.load(f)

    P = int(cfg["p"])
    K = int(cfg["k"])
    D = [int(d) for d in cfg["params"]]
    SA = int(cfg["sa"]); SB = int(cfg["sb"])
    R0 = int(cfg["r0"]); R1 = int(cfg["r1"])
    FA = int(cfg["fa"]); FB = int(cfg["fb"])

    print(f"P={P} K={K} D={D}")
    print(f"sa={SA} sb={SB}")
    print(f"r0={R0} r1={R1}")
    print(f"fa={FA} fb={FB}")
