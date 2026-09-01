#get_params.py
import socket
import json
import hashlib

HOST = "15.232.64.175"
PORT = 13500


def recv_json(sock):
    data = b""

    while b"\n" not in data:
        chunk = sock.recv(65536)

        if not chunk:
            raise EOFError("Server closed connection")

        data += chunk

    line, _, _ = data.partition(b"\n")
    return json.loads(line.decode())


def send_json(sock, obj):
    sock.sendall(
        (json.dumps(obj, separators=(",", ":")) + "\n").encode()
    )


def solve_pow(chal, bits):
    target = 1 << (256 - bits)
    i = 0

    while True:
        s = str(i)

        digest = hashlib.sha256(
            (chal + s).encode()
        ).digest()

        if int.from_bytes(digest, "big") < target:
            return s

        i += 1


sock = socket.create_connection((HOST, PORT))

# Terima PoW
hello = recv_json(sock)

pow_info = hello["pow"]
chal = pow_info["chal"]
bits = pow_info["bits"]

print("[+] Challenge:", chal)
print("[+] Bits:", bits)

# Selesaikan PoW
solution = solve_pow(chal, bits)

print("[+] PoW:", solution)

# Kirim PoW
send_json(sock, {
    "pow": solution
})

# Terima parameter
params = recv_json(sock)

print("[+] Server parameters received")
print("[+] n =", params["n"])
print("[+] q =", params["q"])
print("[+] k =", params["k"])

# Simpan
with open("params.json", "w") as f:
    json.dump(params, f)

print("[+] Saved to params.json")