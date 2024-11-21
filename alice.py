import random
import math
import socket
import time
from utils import *
from pka import pka 

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

# Register Alice to PKA
id_alice = "a001"
e, n, d = pka.generate_key_pair(id_alice)  # Register Alice's keys with the shared PKA

print("Public key (Alice): ", e)
print("Private key (Alice): ", d)
key_alice = "AABB09182736CCDD"
print(f"[Alice] Registered with PKA: {id_alice}")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()
port = 12345
server_socket.bind((host, port))
server_socket.listen()

print(f"Server berjalan di {host}:{port}")

client_socket, addr = server_socket.accept()
print(f"Menerima koneksi dari {addr}")

# Retry logic for obtaining Bob's public key
id_bob = "b001"
max_retries = 5
retry_delay = 2  # seconds

for attempt in range(max_retries):
    bob_public_key = pka.get_public_key(id_bob)
    if bob_public_key:
        break
    print(f"[Alice] Attempt {attempt + 1}: Bob's public key not found. Retrying in {retry_delay} seconds...")
    time.sleep(retry_delay)
else:
    print("Failed to obtain Bob's public key from PKA after multiple attempts.")
    client_socket.close()
    exit()

e_bob, n_bob = bob_public_key
print(f"[Alice] Retrieved Bob's public key: (e={e_bob}, n={n_bob})")

print("[Alice] Sending public key to Bob...")
client_socket.send(str(e).encode())  # Send Alice's public key to Bob
client_socket.send(str(n).encode())

print("[Alice] Waiting to receive Bob's public key...")
e_bob = int(client_socket.recv(1024).decode())
n_bob = int(client_socket.recv(1024).decode())
print(f"[Alice] Received Bob's public key: (e={e_bob}, n={n_bob})")

Na = "123456"
pair_1 = Na + id_alice
print(f"[Alice] Encrypting and sending Na + ID to Bob: {pair_1}")
send_1 = encrypt_rsa(pair_1, e_bob, n_bob)
client_socket.send(str(send_1).encode())

print("[Alice] Waiting to receive Nb and Na from Bob...")
pair_2 = eval(client_socket.recv(1024).decode())
print("Ini pair step 2 dari Bob: ", pair_2)
Nb = pair_2[:6]
print("Nb: ", Nb)
Na_from_bob = ''.join(pair_2[6:])
print("Na_from_bob: ", Na_from_bob)
print("Na: ", Na)

if Na_from_bob == Na:
    print("[Alice] Na is valid")
    Nb = decrypt_rsa(Nb, d, n)

    print("[Alice] Encrypting and sending Nb back to Bob...")
    Nb_encrypted = encrypt_rsa(Nb, e_bob, n_bob)
    client_socket.send(str(Nb_encrypted).encode())
    print("Let's talk with Bob")
    kirim_key_alice = encrypt_rsa(key_alice, e_bob, n_bob)
    client_socket.send(str(kirim_key_alice).encode())

    plaintext = input("Masukkan plaintext yang akan dienkripsi untuk Bob: ")
    chipertext = key_exchange_client(key_alice, plaintext, "encrypt")
    print("Plaintext for Bob: ", plaintext)
    print("Chipertext for Bob: ", chipertext)
    client_socket.send(chipertext.encode())
else:
    print("[Alice] Na is not valid, closing connection.")
    client_socket.close()