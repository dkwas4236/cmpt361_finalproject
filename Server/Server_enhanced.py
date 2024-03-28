# server_enhanced.py
import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256

'''
Need to copy and paste rest of server program into here when it is finished

key = generate_key()
hmac_key = generate_key()

symkey_encrypted = rsa_encrypt(sym_key, client_public_key)
hmackey_encrypted = rsa_encrypt(hmac_key, client_public_key)

# want to send both keys separately to avoid attacker grabbing both at same time
connectionSocket.send(symkey_encrypted)
connectionSocket.send(hmackey_encrypted)

# simple testing functionality to demonstrate tampering
tampered_message = decrypt(connectionSocket, sym_key, hmac_key))
'''

# new function uses hash function SHA256 and nonce (number used once) to enhance security
def encrypt(message, socket, sym_key, hmac_key):
    # generate a nonce
    nonce = get_random_bytes(AES.block_size)

    # append nonce to message
    message_with_nonce = nonce + message.encode()

    # encrypt the message
    cipher = AES.new(sym_key, AES.MODE_ECB)
    cipher_bytes = cipher.encrypt(pad(message_with_nonce, AES.block_size))

    # generate HMAC
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(cipher_bytes)
    hmac_digest = hmac.digest()

    # append HMAC to encrypted message
    encrypted_message = cipher_bytes + hmac_digest

    # printing so that we can demonstrate what it looks like
    print("Encrypted message (in hex): ", cipher_bytes.hex())
    socket.send(encrypted_message)

# new function uses hash function SHA256 and nonce (number used once) to enhance security
def decrypt(socket, sym_key, hmac_key):
    # receive data from the socket ( + SHA256.digest_size = size adjustment needed for the SHA)
    received_data = socket.recv(2048 + SHA256.digest_size)

    # separate encrypted data and HMAC
    encrypted_data = received_data[:-SHA256.digest_size]
    received_hmac = received_data[-SHA256.digest_size:]

    # verify HMAC
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(encrypted_data)
    try:
        hmac.verify(received_hmac)
    except ValueError:
        raise ValueError("Tampering detected. Invalid message or key")

    # decrypt the data
    cipher = AES.new(sym_key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(encrypted_data)

    # remove padding and nonce
    plaintext = unpad(decrypted_data, AES.block_size)[AES.block_size:]

    print("Decrypted message: ", plaintext.decode())
    return plaintext.decode()

def generate_key(key_size=32):
    return get_random_bytes(key_size)