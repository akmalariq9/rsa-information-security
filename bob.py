import socket
from static import *
from des import *
from utils import *
from pka import pka

def bob():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = socket.gethostname()
    port = 12345
    client_socket.connect((host, port))
    print(f"Terhubung ke server di {host}:{port}")
    
    while(True):
        id_alice = "a001"
        id_bob = "b001"
        key_des = "AABB09182736CCDC"
        e, n, d = pka.generate_key_pair(id_bob)
        alice_public_key = pka.get_public_key(id_alice)
        print("Public key (Bob): ", e)
        print("Private key (Bob): ", d)
        print(f"[Bob] Registered with PKA: {id_bob}")

        if not alice_public_key:
            print("Failed to obtain Alice's public key from PKA.")
            client_socket.close()
            exit()

        # Receive Alice's public key from two separate messages
        e_alice = int(client_socket.recv(1024).decode())
        n_alice = int(client_socket.recv(1024).decode())
        print(f"[Bob] Received Alice's public key: (e={e_alice}, n={n_alice})")

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

        if(Nb_from_bob == Nb):
            print("[Bob] Nb is valid")
            key_alice = eval(client_socket.recv(1024).decode())
            key_alice = decrypt_rsa(key_alice, d, n)
            print("[Bob] Waiting to receive encrypted message from Alice...")
            text = client_socket.recv(1024).decode()
            if text == "exit":
                print("Alice has left the chat.")
                break

            if len(text) % 16 != 0:
                chiper_text = text[:-1]
            else:
                chiper_text = text

            print("Cipher Text from Alice: " + chiper_text)
            print("Key : " + key_alice)

            key_alice = hex2bin(key_alice)
            key_alice = permute(key_alice, keyp, 56)
            left = key_alice[0:28]
            right = key_alice[28:56]
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
            print(f"Decrypted plain text from Alice: {plain_text}")
            
            kirim_key_bob = encrypt_rsa(key_des, e_alice, n_alice)
            client_socket.send(str(kirim_key_bob).encode())
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
                print("Cipher Text For Alice : ", original_ct)
                client_socket.send(original_ct.encode())
            client_socket.close()

        else:
            print("[Bob] Nb is invalid")
            client_socket.close()
            break

    client_socket.close()

if __name__ == "__main__":
    bob()
