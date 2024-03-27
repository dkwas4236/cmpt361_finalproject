# Client.py
import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

def client():
    serverPort = 13000

    # retrieve server public keys
    with open('server_public.pem', 'rb') as file:
        server_public_key = RSA.import_key(file.read())

    # Create client socket using IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)
    
    try:
        # Get IP or Server name from user
        serverName = input('Enter the server IP or name: ') 
        # Client connects with the server
        clientSocket.connect((serverName, serverPort))

        # Client receives the initial username message
        usernameReq = clientSocket.recv(2048).decode('ascii') 
        username = input(usernameReq)
        # Send username back to server
        username_encrypted = rsa_encrypt(username, server_public_key)
        clientSocket.send(username_encrypted)
        # Receive password message 
        passwordReq = clientSocket.recv(2048).decode('ascii') 
        password = input(passwordReq)
        # send password back to server
        password_encrypted = rsa_encrypt(password, server_public_key)
        clientSocket.send(password_encrypted)

        # grab the users private key by taking their username
        with open('%s_private.pem' % username, 'rb') as file:
            client_private_key = RSA.import_key(file.read())
        # receive length of encrypted key
        encrypted_length = int.from_bytes(clientSocket.recv(4), 'big')
        # receive the encrypted key based on the length
        symkey_encrypted = b''
        while len(symkey_encrypted) < encrypted_length:
            part = clientSocket.recv(encrypted_length - len(symkey_encrypted))
            symkey_encrypted += part
        sym_key = rsa_decrypt(symkey_encrypted, client_private_key)
        encrypt("OK", clientSocket, sym_key)

        # Receive menu from server
        menu = decrypt(clientSocket, sym_key)
        if not menu.endswith(": "):
            print(menu)
            clientSocket.close()
            sys.exit(1)
         
        # Loop until user termination
        while(1):
            # Display menu and get user choice
            choice = input(menu)
            # Send choice to server
            encrypt(choice, clientSocket, sym_key)
            if choice == "1":
                # Receive destination prompt from the server and get user input
                destinationReq = decrypt(clientSocket, sym_key)
                destinations = input(destinationReq)
                # Send destination(s) to the server 
                encrypt(destinationReq, clientSocket, sym_key)

                # Receive title request from the server 
                titleReq = decrypt(clientSocket, sym_key)
                choice = input(titleReq)
                # Get title from user and send back to server 
                encrypt(choice, clientSocket, sym_key)

                # Receive load file request from the server
                loadFromFileReq = decrypt(clientSocket, sym_key)
                choice = input(loadFromFileReq)
                # Send user input back to server
                encrypt(choice, clientSocket, sym_key)
                
                # Get message content prompt from the server
                contentsReq = decrypt(clientSocket, sym_key)
                print(contentsReq)
                # Send content back to the server
                content = input()
                encrypt(content, clientSocket, sym_key)

            elif choice == "2":
                # Receive inbox list from server 
                inboxlist = decrypt(clientSocket, sym_key)
                print(inboxlist)

            elif choice == "3":
                # Get message from server and get index from user
                index_prompt = decrypt(clientSocket, sym_key)
                #print(f'{index_prompt}{input()}')
                index = input(index_prompt)
                # Send index back to the server 
                encrypt(index, clientSocket, sym_key)
                
            elif choice == "4":
                # Client terminates connection with the server 
                print("The connection is terminated with the server.")
                clientSocket.close()
                sys.exit(1)
         

    except socket.error as e:
        print('An error occurred:', e)
        sys.exit(1)

# RSA decrypt method for INITIAL handshake between client and server
def rsa_decrypt(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message

# RSA encrypt method for INITIAL handshake between client and server
def rsa_encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# encrypts messages sent by client using AES (symmetric keys) (all other encrypts after handshake)
def encrypt(message, socket, key):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    socket.send(cipher_bytes)

# decrypts messages sent by serve using AES (symmetric keys) (all other decrypts after handshake)
def decrypt(socket, key):
    # receive data from the socket
    encrypted_data = socket.recv(2048)

    # decrypt the data
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return plaintext.decode()

# call the client function below
if __name__ == "__main__":
    client()
