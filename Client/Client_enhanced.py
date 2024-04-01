'''
Class: CMPT 361 - AS01
Instructor: Dr. Mahdi D. Firoozjaei
Final Project: Secure Mail Transfer Protocol
Contributors: Brayden van Teeling, Darion Kwasnitza, Hope Oberez, Liam Prsa, Tyler Hardy 
'''

import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

def client():
    serverPort = 13000

    # retrieve server public keys
    dir = os.path.dirname(os.path.abspath(__file__))
    server_public_key_file = os.path.join(dir,"server_public.pem")
    with open(server_public_key_file, 'rb') as file:
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

        # validate authorization
        authorization = clientSocket.recv(2048).decode(('ascii'))
        if authorization == "AUTHORIZED":
            # grab the users private key by taking their username
            client_private_key_file = os.path.join(dir, '%s_private.pem' % username)
            with open(client_private_key_file, 'rb') as file:
                client_private_key = RSA.import_key(file.read())

            # receive length of encrypted sym key
            encrypted_length = int.from_bytes(clientSocket.recv(4), 'big')
            # receive the encrypted sym key based on the length
            symkey_encrypted = b''
            while len(symkey_encrypted) < encrypted_length:
                part = clientSocket.recv(encrypted_length - len(symkey_encrypted))
                symkey_encrypted += part
            sym_key = rsa_decrypt(symkey_encrypted, client_private_key)

            # receive length of encrypted hmac key
            encrypted_length = int.from_bytes(clientSocket.recv(4), 'big')
            hmackey_encrypted = b''
            while len(hmackey_encrypted) < encrypted_length:
                part = clientSocket.recv(encrypted_length - len(hmackey_encrypted))
                hmackey_encrypted += part
            
            # decrypt both keys
            sym_key = rsa_decrypt(symkey_encrypted, client_private_key)
            hmac_key = rsa_decrypt(hmackey_encrypted, client_private_key)
            encrypt("OK", clientSocket, sym_key, hmac_key)
        else:
            termination = clientSocket.recv(2048).decode('ascii')
            print(termination)
            sys.exit(1)

        # Receive menu from server
        menu = decrypt(clientSocket, sym_key, hmac_key)

        # Loop until user termination
        while(1):
            # Display menu and get user choice
            choice = input(menu)
            # Send choice to server
            encrypt(choice, clientSocket, sym_key, hmac_key)
            if choice == "1":
                # get email prompt 
                emailPrompt = decrypt(clientSocket, sym_key, hmac_key)
                if emailPrompt == "Send the email":
                    # Get destinations from user 
                    destinations = input("Enter destinations (seperated by;): ")
                    # Get title from user
                    title = input("Enter Title: ")
                  # loop until inputs are successful 
                    while True:
                         # Does the user want to attach a file to the email?
                        fileAttached = input("Would you like to load contents from a file?(Y/N) ")
                        accepted_inputs = ["y","Y","N","n"]
                        while(fileAttached.strip() not in accepted_inputs):
                            fileAttached = input("Would you like to load contents from a file?(Y/N) ")
                        if (fileAttached.strip() == 'N' or fileAttached.strip() == 'n'):
                            # Content recieved from command line 
                            print("Enter Message Contents: ")
                            contents = input()
                            # Do not need to error check for file, break loop
                            break
                        else:
                            filename = input("Enter filename: ")
                            try:
                                # If file is found break loop
                                with open(os.path.join(dir,filename),'r') as file:
                                    contents = file.read()
                                break
                            except:
                                # File was not found. Display error and restart loop
                                print(f"File '{filename}' was not found.")

                    # Create email and send
                    email = create_email(username,destinations,title,contents)
                    send_email(email,clientSocket,sym_key,hmac_key)
    
            elif choice == "2":
                 # receive header from server
                header = decrypt(clientSocket, sym_key, hmac_key)
                # Display header
                print(header)
                # Receive inbox list from server loop and decrypt until END_OF_EMAILS
                # using receive email ensures that if inbox is large, client will receive
                # all of it 
                inbox = receive_email(clientSocket,sym_key, hmac_key)
           
                print(inbox.split("END_OF_EMAILS")[0])

            elif choice == "3":
               # Get message from server and get index from user
                index_prompt = decrypt(clientSocket, sym_key, hmac_key)
                # Get index from user
                index = input(index_prompt)
                encrypt(index, clientSocket, sym_key, hmac_key)

                # Get email from server
                email = receive_email(clientSocket, sym_key, hmac_key)
                # Display email
                print(f"\n{email}")
                
            elif choice == "4":
                # Client terminates connection with the server 
                print("The connection is terminated with the server.")
                clientSocket.close()
                sys.exit(1)
         

    except socket.error as e:
        print('An error occurred:', e)
        sys.exit(1)

'''
Need to copy and paste rest of client program into here when it is finished

# simple testing functionality to demonstrate tampering
message = 'Hello World!'
encrypt(message, clientSocket, sym_key, hmac_key)
'''

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

def create_email(username,destinations,title,content):
    email =f"From: {username}\nTo: {destinations}\n"
    # check length of title and add to email
    if len(title) > 100: 
        title = title[0:99]
    email += f"Title: {title}\n"
    # check for txt file or command line entry 

    if len(content)>1000000:
        content = content[0:999999]
    email += f"Content Length: {len(content)}\nContent:\n{content}"
    return email

def send_email(email,socket,symkey, hmac_key):
    # generate a nonce
    nonce = get_random_bytes(AES.block_size)
    # append nonce and end of email marker to message
    # combine email and end marker
    email = email + "END_OF_EMAIL"
    email = nonce + email.encode()

    # generate HMAC
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    
    cipher = AES.new(symkey, AES.MODE_ECB)
    
    # Check to see if message needs padding, then encrpyt 
    if len(email) % 16 != 0:
        padded_email = pad(email, AES.block_size)
        encrypted_email = cipher.encrypt(padded_email)
        hmac.update(encrypted_email)
        hmac_digest = hmac.digest()
        encrypted_email = encrypted_email + hmac_digest
    else:
        encrypted_email = cipher.encrypt(email)
        hmac.update(encrypted_email)
        hmac_digest = hmac.digest()
        encrypted_email = encrypted_email + hmac_digest
   
    # send encrypted data in chunks
    chunk_size = 2048
    for i in range(0, len(encrypted_email), chunk_size):
        chunk = encrypted_email[i:i + chunk_size]
        socket.send(chunk)

def receive_email(socket, symkey, hmac_key):
    cipher = AES.new(symkey, AES.MODE_ECB)
    encrypted_email = b''
    count = 0
    while True:
        # receive data from the socket ( + SHA256.digest_size = size adjustment needed for the SHA)
        chunk = socket.recv(2048 + SHA256.digest_size)

        # separate encrypted data and HMAC
        encrypted_chunk = chunk[:-SHA256.digest_size]
        chunk_hmac = chunk[-SHA256.digest_size:]

        # verify HMAC
        hmac = HMAC.new(hmac_key, digestmod=SHA256)
        hmac.update(encrypted_chunk)
        #try:
        #    hmac.verify(chunk_hmac)
        #except ValueError:
        #    raise ValueError("Tampering detected. Invalid message or key")

        # Add encrypted data to email
        if count == 0:
            encrypted_email += encrypted_chunk[AES.block_size:]
        else:
            encrypted_email += encrypted_chunk

        # check if entire message has been received
        try:
            decrypted_email = cipher.decrypt(encrypted_email).decode()
            #print(decrypted_email)
            if "END_OF_EMAIL" in decrypted_email:
                email = decrypted_email.split("END_OF_EMAIL")[0]
                break
        except ():
            # continue receiving more data if message is incomplete
            continue
        count += 1
    # in case loop exits without returning (it shouldn't in normal conditions)
    return email

# call the client function below
if __name__ == "__main__":
    client()