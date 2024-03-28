# client_enhances.py
import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

'''
Need to copy and paste rest of client program into here when it is finished

# simple testing functionality to demonstrate tampering
message = 'Hello World!'
encrypt(message, clientSocket, sym_key, hmac_key)
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
    encrypted_message_with_hmac = cipher_bytes + hmac_digest

    socket.send(encrypted_message_with_hmac)

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
    decrypted_data_with_nonce = cipher.decrypt(encrypted_data)

    # remove padding and nonce
    plaintext = unpad(decrypted_data_with_nonce, AES.block_size)[AES.block_size:]

    return plaintext.decode()

# function that tampers with data to test new HMAC functionality
def tamper_data(data):
    # change bytes in encrypted data to simulate tampering
    tampered_data = bytearray(data)
    # flip bit in data
    tampered_data[10] = tampered_data[10] ^ 1
    return bytes(tampered_data)

# generates a 256 AES key ( 256 = 32 bytes) that will be exchanged with client
# can also generate an HMAC key
def generate_key(key_size=32):
    return get_random_bytes(key_size)