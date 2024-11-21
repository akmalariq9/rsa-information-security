import socket
from static import *
from des import *
from utils import *
from pka import pka
import ast
import time

def alice():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 12345
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"Server berjalan di {host}:{port}")
    client_socket, addr = server_socket.accept()
    print(f"Menerima koneksi dari {addr}")

    while(True):
        key_des = "AABB09182736CCDD"
        id_alice = "a001"
        id_bob = "b001"
        N_alice = "123456"
        pair_1 = N_alice + id_alice
        e, n, d = pka.generate_key_pair(id_alice)  # Fixed self_generate_key to pka.generate_key_pair
        key_sign = str(encrypt_rsa(key_des, d, n))
        print(f"[Alice] Registered with PKA: {id_alice}")
        print("Let's Talks with bob")
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

        # Send Alice's public key to Bob
        client_socket.send(f"{e}".encode())
        time.sleep(0.1)  # Ensure proper separation in transmission
        client_socket.send(f"{n}".encode())

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
        print("Na : ", N_alice)
        
        if Na_from_bob == N_alice:
            print("[Alice] Na is valid")
            Nb = decrypt_rsa(Nb, d, n)
            print("[Alice] Encrypting and sending Nb back to Bob...")
            Nb_encrypted = encrypt_rsa(Nb, e_bob, n_bob)
            client_socket.send(str(Nb_encrypted).encode())

            print("Let's talk with Bob")
            kirim_key_alice = encrypt_rsa(key_des, e_bob, n_bob)
            client_socket.send(str(kirim_key_alice).encode())
            plain_text = input("Masukkan Plaintext (atau ketik 'exit' untuk keluar): ")
            if plain_text != "exit":
                print("Plaintext: " + plain_text)
                print("Key: " + key_des)
                key_des = hex2bin(key_des)
                key_des = permute(key_des, keyp, 56)
                left = key_des[0:28]
                right = key_des[28:56]
                rkb = []
                rk = []
            
                for i in range(0, 16):
                    left = shift_left(left, shift_table[i])
                    right = shift_left(right, shift_table[i])
                    combine_str = left + right
                    round_key = permute(combine_str, key_comp, 48)
                    rkb.append(round_key)
                    rk.append(bin2hex(round_key))
            
                print("Encryption")
                ct, added_char = ecb_encrypt(plain_text, rkb, rk)
                original_ct = bin2hex(ct) + added_char
                print("Cipher Text For Bob : ", original_ct)
                client_socket.send(original_ct.encode())    
            else:
                client_socket.send("exit".encode())
                break
            
            key_bob = eval(client_socket.recv(1024).decode())
            key_bob = decrypt_rsa(key_bob, d, n)
            
            print("[Alice] Waiting to receive encrypted message from Bob...")
            text = client_socket.recv(1024).decode()
            if text == "exit":
                print("Bob has left the chat.")
                break
            if len(text) % 16 != 0:
                chiper_text = text[:-1]
            else:
                chiper_text = text

            print("Cipher Text from Bob: " + chiper_text)
            print("Key : " + key_bob)

            key_bob = hex2bin(key_bob)
            key_bob = permute(key_bob, keyp, 56)
            left = key_bob[0:28]
            right = key_bob[28:56]
            rkb = []
            rk = []

            for i in range(0, 16):
                left = shift_left(left, shift_table[i])
                right = shift_left(right, shift_table[i])
                combine_str = left + right
                round_key = permute(combine_str, key_comp, 48)
                rkb.append(round_key)
                rk.append(bin2hex(round_key))
            rk_reverse = rk[::-1]
            rkb_reverse = rkb[::-1]
            plain_text = bin2hex(ecb_decrypt(chiper_text, rkb_reverse, rk_reverse))
            if len(text) % 16 != 0:
                padding_len = bin2dec(int(hex2bin(text[-1])))
                plain_text = plain_text[:-padding_len]
            print(f"Decrypted plain text from Bob: {plain_text}")
        else:
            client_socket.send("exit".encode())
            break

if __name__ == '__main__':
    alice()
