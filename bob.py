import random
import math
import socket
from utils import *
from pka import *

def encrypt(pt, rkb, rk):
    pt = hex2bin(pt)
    pt = permute(pt, initial_perm, 64)
    left = pt[0:32]
    right = pt[32:64]
    for i in range(1, 17):
        right_expanded = permute(right, exp_d, 48)
        xor_x = xor(right_expanded, rkb[i-1])
        sbox_str = ""
        for j in range(0, 8):
            row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
            col = bin2dec(
                int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
            val = sbox[j][row][col]
            sbox_str = sbox_str + dec2bin(val)
        sbox_str = permute(sbox_str, per, 32)
        result = xor(left, sbox_str)
        left = result
        if (i != 16):
            left, right = right, left
    combine = left + right
    cipher_text = permute(combine, final_perm, 64)
    return cipher_text


def key_exchange_client(keys, text, type):
    # Konversi kunci menjadi format yang sesuai
    key = hex2bin(keys)
    key = permute(key, keyp, 56)

    left = key[0:28]
    right = key[28:56]

    rkb = []
    rk = []

    for i in range(0, 16):
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        combine_str = left + right
        round_key = permute(combine_str, key_comp, 48)
        rkb.append(round_key)
        rk.append(bin2hex(round_key))

    # Menambahkan padding jika panjang kurang dari 16 karakter
    if len(text) % 16 != 0:
        text = text.ljust(((len(text) // 16) + 1) * 16, '0')

    result = ""
    # Enkripsi atau dekripsi tiap blok
    for i in range(0, len(text), 16):
        block = text[i:i+16]
        if type == "encrypt":
            result += bin2hex(encrypt(block, rkb, rk))
        elif type == "decrypt":
            rkb_rev = rkb[::-1]
            rk_rev = rk[::-1]
            result += bin2hex(encrypt(block, rkb_rev, rk_rev))

    return result


def encrypt_rsa(msg, e, n):
    msg_encoded = [ord(c) for c in msg]
    chipertext = [pow(c, e, n) for c in msg_encoded]
    return chipertext


def decrypt_rsa(chipertext, d, n):
    msg_encoded = [pow(ch, d, n) for ch in chipertext]
    msg = ''.join([chr(c) for c in msg_encoded])
    return msg


p, q = generate_prime(100, 1000), generate_prime(100, 1000)
while p == q:
    q = generate_prime(100, 1000)
n = p * q
phi_n = (p - 1) * (q - 1)
e = random.randint(3, phi_n-1)

while math.gcd(e, phi_n) != 1:
    e = random.randint(3, phi_n-1)
d = mod_inverse(e, phi_n)

id_bob = "b001"
e, n, d = pka.generate_key_pair(id_bob)  # Register Bob's keys with the shared PKA

print("Public key (Bob): ", e)
print("Private key (Bob): ", d)
print(f"[Bob] Registered with PKA: {id_bob}")

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()
port = 12345
client_socket.connect((host, port))
print(f"Terhubung ke server di {host}:{port}")

# Obtain Alice's public key from PKA
id_alice = "a001"
alice_public_key = pka.get_public_key(id_alice)

if not alice_public_key:
    print("Failed to obtain Alice's public key from PKA.")
    client_socket.close()
    exit()

e_alice, n_alice = alice_public_key
print(f"[Bob] Retrieved Alice's public key: (e={e_alice}, n={n_alice})")

print("[Bob] Waiting to receive Alice's public key...")
e_alice = int(client_socket.recv(1024).decode())
n_alice = int(client_socket.recv(1024).decode())
print(f"[Bob] Received Alice's public key: (e={e_alice}, n={n_alice})")

print("[Bob] Sending public key to Alice...")
client_socket.send(str(e).encode())  # Send Bob's public key to Alice
client_socket.send(str(n).encode())

print("[Bob] Waiting to receive encrypted Na + ID from Alice...")
Na = eval(client_socket.recv(1024).decode())
id_a = Na[6:]
Na = Na[:6]
Na = decrypt_rsa(Na, d, n)

Nb = "778899"
pair_1 = Nb + id_bob
Nb_encrypted = encrypt_rsa(Nb, e_alice, n_alice)
pair_2 = Nb_encrypted + [Na]
print(f"[Bob] Sending encrypted Nb and Na back to Alice: {pair_2}")
client_socket.send(str(pair_2).encode())

print("[Bob] Waiting to receive encrypted Nb back from Alice...")
Nb_from_bob = eval(client_socket.recv(1024).decode())
Nb_from_bob = decrypt_rsa(Nb_from_bob, d, n)

if Nb_from_bob == Nb:
    print("[Bob] Nb is valid")
    key_alice = eval(client_socket.recv(1024).decode())
    key_alice = decrypt_rsa(key_alice, d, n)

    print("[Bob] Waiting to receive encrypted message from Alice...")
    chipertext_from_alice = client_socket.recv(1024).decode()
    plaintext = key_exchange_client(key_alice, chipertext_from_alice, "decrypt")
    print("Plaintext from Alice: ", plaintext)
    print("Chipertext from Alice: ", chipertext_from_alice)
else:
    print("[Bob] Nb is not valid, closing connection.")
    client_socket.close()