import random
import math
import json
import os
from utils import generate_prime, mod_inverse

class PublicKeyAuthority:
    _instance = None
    storage_file = "pka_storage.json"

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(PublicKeyAuthority, cls).__new__(cls)
            cls._instance.registered_keys = cls._instance._load_registered_keys()
        return cls._instance

    def _load_registered_keys(self):
        if os.path.exists(self.storage_file):
            with open(self.storage_file, 'r') as file:
                try:
                    return json.load(file)
                except json.JSONDecodeError:
                    return {}
        return {}

    def _save_registered_keys(self):
        with open(self.storage_file, 'w') as file:
            json.dump(self.registered_keys, file)

    def generate_key_pair(self, client_id):
        if client_id not in self.registered_keys:
            p, q = generate_prime(100, 1000), generate_prime(100, 1000)
            while p == q:
                q = generate_prime(100, 1000)
            n = p * q
            phi_n = (p - 1) * (q - 1)
            e = random.randint(3, phi_n - 1)
            while math.gcd(e, phi_n) != 1:
                e = random.randint(3, phi_n - 1)
            d = mod_inverse(e, phi_n)
            self.registered_keys[client_id] = {'public': (e, n), 'private': d}
            print(f"[PKA] Registered client '{client_id}' with public key (e={e}, n={n})")
            self._save_registered_keys()
        else:
            print(f"[PKA] Client '{client_id}' is already registered.")
        return self.registered_keys[client_id]['public'][0], self.registered_keys[client_id]['public'][1], self.registered_keys[client_id]['private']

    def get_public_key(self, client_id):
        if client_id in self.registered_keys:
            print(f"[PKA] Retrieved public key for client '{client_id}': {self.registered_keys[client_id]['public']}")
            return self.registered_keys[client_id]['public']
        print(f"[PKA] No public key found for client '{client_id}'")
        return None

# Create a shared singleton instance of PKA
pka = PublicKeyAuthority()
