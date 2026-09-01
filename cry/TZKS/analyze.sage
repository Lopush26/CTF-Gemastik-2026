#analyze.sage
import json

with open("params.json") as f:
    obj = json.load(f)

n = obj["n"]
q = obj["q"]
k = obj["k"]

print(f"[+] n = {n}")
print(f"[+] q = {q}")
print(f"[+] k = {k}")

# Ring: Z_q[x] / (x^n + 1)
P.<x> = PolynomialRing(GF(q))
R.<X> = P.quotient(x^n + 1)


def decode(h):
    coeffs = [
        Integer(h[i:i+6], 16)
        for i in range(0, len(h), 6)
    ]

    return R(P(coeffs))


# Buat matrix A
A = matrix(R, k, k, [
    decode(obj["A"][i][j])
    for i in range(k)
    for j in range(k)
])

# Buat vector T
T = vector(R, [
    decode(x)
    for x in obj["t"]
])

print("[+] A constructed")
print("[+] T constructed")

print("[*] Solving A*S = T ...")

try:
    S = A.solve_right(T)

    print("[+] A*S = T is solvable")

    for i, s in enumerate(S):
        coeffs = list(s.lift())

        signed = []

        for c in coeffs:
            c = int(c)

            if c > q // 2:
                c -= q

            signed.append(c)

        print(
            f"S[{i}]: "
            f"maxabs={max(map(abs, signed))}, "
            f"min={min(signed)}, "
            f"max={max(signed)}"
        )

except Exception as e:
    print("[-] A*S=T failed:")
    print(e)