import random
import math
from des import *
def is_prime(number):
    if number < 2:
        return False
    for i in range(2, number // 2+1):
        if number % i == 0:
            return False
    return True

def generate_prime(min_value, max_value):
    prime = random.randint(min_value, max_value)
    while not is_prime(prime):
        prime = random.randint(min_value, max_value)
    return prime

def mod_inverse(e, phi):
    for d in range(3, phi):
        if (d * e) % phi == 1:
            return d
    return ValueError('No mod inverse found')

def encrypt_rsa(msg, e, n):
    msg_encoded = [ord(c) for c in msg]
    chipertext = [pow(c, e, n) for c in msg_encoded]
    return chipertext


def decrypt_rsa(chipertext, d, n):
    msg_encoded = [pow(ch, d, n) for ch in chipertext]
    msg = ''.join([chr(c) for c in msg_encoded])
    return msg

def self_generate_key():
    p, q = generate_prime(100, 1000), generate_prime(100, 1000)

    while p == q:
        q = generate_prime(100, 1000)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = random.randint(3, phi_n-1)

    while math.gcd(e, phi_n) != 1:
        e = random.randint(3, phi_n-1)
    d = mod_inverse(e, phi_n)
    return e, n, d

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
