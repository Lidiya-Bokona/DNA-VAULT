from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
import os
from Crypto.Random import get_random_bytes
import binascii

# Try to generate a key
key = get_random_bytes(64)
print("AES-512 key generated successfully")

# Print the key in hexadecimal format (more useful for debugging)
print("Key (hex):", binascii.hexlify(key).decode())

# Example of using the key (you'll need to add encryption/decryption logic)
print("Key length (bytes):", len(key))

#You can perform encryption and decryption here