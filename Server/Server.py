# Server.py
import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def server():
    serverPort = 13000

    # retrieve the servers private keys
    dir = os.path.dirname(os.path.abspath(__file__))
    server_private_key_file = os.path.join(dir,"server_private.pem")
    with open(server_private_key_file, 'rb') as file:
        server_private_key = RSA.import_key(file.read())

    while True:
        try:
            serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverSocket.bind(('', serverPort))
            serverSocket.listen(1)
        except socket.error as e:
            print('Error in server socket binding:', e)
            sys.exit(1)

        while True:
            try:
                connectionSocket, addr = serverSocket.accept()
                child_pid = os.fork()
                if child_pid == 0:  
                    # Send Username message to server
                    usernameMessage = ("Enter your username: ")
                    connectionSocket.send(usernameMessage.encode('ascii'))
                    # Receive Username
                    encrypted_username = connectionSocket.recv(2048)
                    username = rsa_decrypt(encrypted_username, server_private_key).decode()
                    # Send Password message to server 
                    passwordMessage = ("Enter your password: ")
                    connectionSocket.send(passwordMessage.encode('ascii'))
                    # Receive password
                    encrypted_password = connectionSocket.recv(2048)
                    password = rsa_decrypt(encrypted_password, server_private_key).decode()

                    # get directory of user_pass.json
                    # dir = os.path.dirname(os.path.abspath(__file__))
                    user_pass = os.path.join(dir,"user_pass.json")
                    # Open user_pass file and read dictonary
                    with open(user_pass, 'rb') as users:
                        data = json.load(users)
                  
                    # check if username & password is valid
                    authorization = " "
                    sym_key = None
                    for db_username in data.keys():
                        if db_username == username:
                            db_password = data[db_username]
                            if password == db_password:
                                authorization = "AUTHORIZED"
                                connectionSocket.send(authorization.encode('ascii'))
                                # retrieve the clients public keys
                                client_public_key_file = os.path.join(dir,'%s_public.pem' % username)
                                with open(client_public_key_file, 'rb') as file:
                                    client_public_key = RSA.import_key(file.read())
                                # create the sym_key, encode it, and send it
                                sym_key = generate_key()
                                symkey_encrypted = rsa_encrypt(sym_key, client_public_key)
                                # send length of encrypted key
                                connectionSocket.send(len(symkey_encrypted).to_bytes(4, 'big'))
                                connectionSocket.send(symkey_encrypted)
                                print("Connection Accepted and Symmetric Key Generated for client: " + username)
                                break

                    if authorization == "AUTHORIZED":
                        # receive the "OK"
                        decrypt(connectionSocket, sym_key)
                        # Create menu prompts and sent to the client
                        menuMessage = ("\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nChoice: ")
                        encrypt(menuMessage, connectionSocket, sym_key)

                        while (1):
                            # Receive user chice from client 
                            decodedChoice = decrypt(connectionSocket, sym_key)

                            if decodedChoice == "1":
                                # Send destination prompt to the client 
                                emailPrompt = "Send the email"
                                encrypt(emailPrompt,connectionSocket,sym_key)

                                # Get email from client 
                                email = receive_email(connectionSocket,sym_key)

                                email_fields = email.splitlines()

                                for field in email_fields:
                                    # Get "from" line
                                    if field.startswith("From:"):
                                        sending_user = field.split(": ")[-1]
                                    # Get "sent to" line 
                                    if field.startswith("To:"):
                                        user_string = field.split(": ")[-1]
                                        users = user_string.strip().split(";")
                                        # create and add date abd time field to email
                                        now = datetime.datetime.now()
                                        field_datetime = f"Time and Date: {now}"
                                    if field.startswith("Title:"):
                                        title = field.split(": ")[-1].strip()
                                    # Get "content length" line
                                    if field.startswith("Content Length:"):
                                        length = field.split(": ")[-1]
                                # create email with date and time
                                email_fields.insert(2,field_datetime)
                                email = '\n'.join(str(field) for field in email_fields)
                                print(f"An email from {sending_user} is sent to {user_string} has a content length of {length}\n")
                                store_emails(users,title,email,sending_user)

                            elif decodedChoice == "2":
                                # Get inbox list and send to server
                                inboxlist = "Inbox List Info Displayed"
                                encrypt(inboxlist, connectionSocket, sym_key)

                            elif decodedChoice == "3":
                                # Send prompt to server
                                response = "Enter the email index you wish to view: "
                                encrypt(response, connectionSocket, sym_key)
                                # Receive index from user
                                index = decrypt(connectionSocket, sym_key)
                                print(index)

                            elif decodedChoice == "4":
                                # terminate connection
                                print("Terminating connection with " + username)
                                connectionSocket.close()
                                sys.exit(1)

                            else:
                                print("Invalid choice.")

                    else:
                        connectionSocket.send(authorization.encode('ascii'))
                        print("The received client information: " + username + " is invalid (Connection Terminated).")
                        terminationMessage = "Invalid username or password.\nTerminating."
                        connectionSocket.send(terminationMessage.encode('ascii'))
                        connectionSocket.close()

            except socket.error as e:
                print('An error occurred:', e)
                serverSocket.close()
                sys.exit(1)
            except Exception as e:
                print('An unexpected error occurred:', e)
                serverSocket.close()
                sys.exit(1)

# RSA decrypt method for INITIAL handshake between client and server
def rsa_decrypt(encrypted_message, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message

# RSA encrypt method for INITIAL handshake between client and server
def rsa_encrypt(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

# encrypts messages sent by server using AES (symmetric keys) (all other encrypts after handshake)
def encrypt(message, socket, key):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    socket.send(cipher_bytes)

# decrypts messages sent by client using AES (symmetric keys) (all other decrypts after handshake)
def decrypt(socket, key):
    # receive data from the socket
    encrypted_data = socket.recv(2048)

    # decrypt the data
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return plaintext.decode()

def receive_email(socket, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_email = b''

    while True:
        chunk = socket.recv(2048)

        encrypted_email += chunk

        # check if entire message has been received
        try:
            decrypted_email = unpad(cipher.decrypt(encrypted_email), AES.block_size).decode()
            if "END_OF_EMAIL" in decrypted_email:
                email = decrypted_email.split("END_OF_EMAIL")[0]
                return email
        except ():
            # continue receiving more data if message is incomplete
            continue

    # in case loop exits without returning (it shouldn't in normal conditions)
    return None

def store_emails(users,title,email,sender):
    for user in users:
        dir = os.path.dirname(os.path.abspath(__file__))
        filename = f'{user}/{sender}_{title.replace(" ","_")}.txt'
        with open(os.path.join(dir,filename), 'w') as email_file:
            email_file.write(email)

# generates a 256 AES key ( 256 = 32 bytes) that will be exchanged with client
def generate_key(key_size=32):
    return get_random_bytes(key_size)

# call the server function below
if __name__ == "__main__":
    server()

