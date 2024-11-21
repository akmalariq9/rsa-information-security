from static import *
import random

def hex2bin(s):
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011", '4': "0100",
          '5': "0101", '6': "0110", '7': "0111", '8': "1000", '9': "1001",
          'A': "1010", 'B': "1011", 'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    bin_result = ""
    i = 0
    while i < len(s):
        bin_result += mp[s[i]]
        i += 1
    return bin_result

def bin2hex(s):
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3', "0100": '4', 
          "0101": '5', "0110": '6', "0111": '7', "1000": '8', "1001": '9', 
          "1010": 'A', "1011": 'B', "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    hex_result = ""
    i = 0
    while i < len(s):
        ch = s[i] + s[i + 1] + s[i + 2] + s[i + 3]
        hex_result += mp[ch]
        i += 4
    return hex_result

def bin2dec(binary):
    decimal = 0
    i = 0
    while binary != 0:
        dec = binary % 10
        decimal += dec * pow(2, i)
        binary //= 10
        i += 1
    return decimal

def dec2bin(num):
    res = bin(num).replace("0b", "")
    if len(res) % 4 != 0:
        div = len(res) // 4
        counter = (4 * (div + 1)) - len(res)
        i = 0
        while i < counter:
            res = '0' + res
            i += 1
    return res

def permute(k, arr, n):
    permutation = ""
    i = 0
    while i < n:
        permutation += k[arr[i] - 1]
        i += 1
    return permutation

def shift_left(k, nth_shifts):
    s = ""
    i = 0
    while i < nth_shifts:
        j = 1
        while j < len(k):
            s += k[j]
            j += 1
        s += k[0]
        k = s
        s = ""
        i += 1
    return k

def xor(a, b):
    ans = ""
    i = 0
    while i < len(a):
        if a[i] == b[i]:
            ans += "0"
        else:
            ans += "1"
        i += 1
    return ans

def key_generator():
    key = ''
    characters = '123456789ABCDEF'

    for _ in range(16): 
        key += random.choice(characters)

    return key

def encrypt(pt, rkb, rk):
    pt = hex2bin(pt)

    pt = permute(pt, initial_perm, 64)
    print("After initial permutation", bin2hex(pt))
    print("| Round     |  left      |  Right     |  round key ")

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
        print("| Round ", i, " | ", bin2hex(left),
              " | ", bin2hex(right), " | ", rk[i-1])
        
    combine = left + right
    ct = permute(combine, final_perm, 64)
    return ct

def add_padding(plaintext):
    padding_length = 16 - (len(plaintext) % 16)
    padding_char = "0" * padding_length
    padding_info = bin2hex(dec2bin(padding_length))
    return plaintext + padding_char, padding_info

def ecb_encrypt(plaintext, round_keys_bin, round_keys_hex):
    padding_info = ""
    if len(plaintext) % 16 != 0:
        plaintext, padding_info = add_padding(plaintext)
    ciphertext = ""
    total_blocks = len(plaintext) // 16

    for block_index in range(total_blocks):
        current_block = plaintext[block_index * 16: (block_index + 1) * 16]
        encrypted_block = encrypt(
            current_block, round_keys_bin, round_keys_hex)
        ciphertext += encrypted_block

    return ciphertext, padding_info
def ecb_decrypt(ciphertext, round_keys_bin, round_keys_hex):
    decrypted_text = ""
    total_blocks = len(ciphertext) // 16

    for block_index in range(total_blocks):
        current_block = ciphertext[block_index * 16: (block_index + 1) * 16]
        decrypted_block = encrypt(
            current_block, round_keys_bin, round_keys_hex)
        decrypted_text += decrypted_block
    return decrypted_text