'''
Class: CMPT 361 - AS01
Instructor: Dr. Mahdi D. Firoozjaei
Final Project: Secure Mail Transfer Protocol
Contributors: Brayden van Teeling, Darion Kwasnitza, Hope Oberez, Liam Prsa, Tyler Hardy 
'''

import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256


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
                                hmac_key = generate_key()
                                symkey_encrypted = rsa_encrypt(sym_key, client_public_key)
                                hmackey_encrypted = rsa_encrypt(hmac_key, client_public_key)
                                # send length of encrypted sym key
                                connectionSocket.send(len(symkey_encrypted).to_bytes(4, 'big'))
                                connectionSocket.send(symkey_encrypted)
                                # send length of encrypted hmac key
                                connectionSocket.send(len(hmackey_encrypted).to_bytes(4, 'big'))
                                connectionSocket.send(hmackey_encrypted)
                                print("Connection Accepted and Symmetric Key Generated for client: " + username)
                                break

                    if authorization == "AUTHORIZED":
                        # receive the "OK"
                        decrypt(connectionSocket, sym_key, hmac_key)
                        # Create menu prompts and sent to the client
                        menuMessage = ("\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4) Terminate the connection\nChoice: ")
                        encrypt(menuMessage, connectionSocket, sym_key, hmac_key)

                        while (1):
                            # Receive user chice from client 
                            decodedChoice = decrypt(connectionSocket, sym_key, hmac_key)

                            if decodedChoice == "1":
                                # Send destination prompt to the client 
                                emailPrompt = "Send the email"
                                encrypt(emailPrompt,connectionSocket,sym_key, hmac_key)

                                # Get email from client 
                                email = receive_email(connectionSocket,sym_key,hmac_key)
                                #print(email)
                                # Track until all headers are recorded
                                count = 0
                                email_fields = email.splitlines()
                                for field in email_fields:
                                    # Get "from" line
                                    if field.startswith("From:"):
                                        sending_user = field.split(": ")[-1]
                                        count+=1
                                    # Get "sent to" line 
                                    if field.startswith("To:"):
                                        user_string = field.split(": ")[-1]
                                        users = user_string.strip().split(";")
                                        # create and add date abd time field to email
                                        now = datetime.datetime.now()
                                        field_datetime = f"Time and Date: {now}"
                                        count+=1
                                    # Get title line
                                    if field.startswith("Title:"):
                                        title = field.split(": ")[-1].strip()
                                        count+=1
                                    # Get "content length" line
                                    if field.startswith("Content Length:"):
                                        length = field.split(": ")[-1]
                                        count+=1
                                    # If all headers are record break out of loop
                                    if count == 4:
                                        break
                                # create email with date and time
                                email_fields.insert(2,field_datetime)
                                email = '\n'.join(str(field) for field in email_fields)
                                print(f"An email from {sending_user} is sent to {user_string} has a content length of {length}")
                                store_emails(users,title,email,sending_user)

                            elif decodedChoice == "2":
                                # based off of the clients username access the proper path to the folder where their emails are stored
                                user_dir = os.path.join(dir, username)
                                # get all the files in the users directory
                                files = glob.glob(user_dir + '/*.txt')
                                # create a list to store the email subprotocol for the client example of subprotocol below
                                #Index From          DateTime             Title
                                #1     client2 2022-07-21 19:29:35.768508 Test2 
                                # create list header
                                header = "Index   From          DateTime                      Title"
                                # send the header and email list to the client
                                encrypt(header, connectionSocket, sym_key, hmac_key)
                            
                                email_list = []
                                # loop through all the files in the users directory and get the email information index, sender, date, and title
                                count = 0
                                for file in files:
                                    count += 1
                                    with open(file, 'r') as email_file:
                                        email = email_file.readlines()
                                        # get the sender
                                        sender = email[0].split(": ")[1].strip()
                                        # get the date and time
                                        date_time = email[2].split(": ")[1].strip()
                                        # get the title
                                        title = email[3].split(": ")[1].strip()
                                        # append the email information to the list
                                        email_list.append(f"{count:<7} {sender:<14} {date_time:<28} {title}")
                                # send the email list to the client
                                #for email in email_list:
                                #   encrypt(email, connectionSocket, sym_key)
                                send_email("\n".join(email_list),connectionSocket,sym_key,hmac_key)
                                # send the end of emails tag
                                #encrypt("END_OF_EMAILS", connectionSocket, sym_key, hmac_key)
                            elif decodedChoice == "3":
                                # get the index from the client
                                response = "Enter the email index you wish to view: "
                                encrypt(response, connectionSocket, sym_key, hmac_key)
                                # based off of the clients username access the proper path to the folder where their emails are stored
                                user_dir = os.path.join(dir, username)
                                # get all the files in the users directory
                                files = glob.glob(user_dir + '/*.txt')

                                # get the index from the client check if smaller then or equal to the number of files
                                index = int(decrypt(connectionSocket, sym_key, hmac_key))
                                
                                # get the email from the file and send it to the client
                                if index <= len(files):
                                    with open(files[index-1], 'r') as email_file:
                                        email = email_file.read()
                                        send_email(email, connectionSocket, sym_key, hmac_key)
                                else:
                                    encrypt("Invalid index", connectionSocket, sym_key, hmac_key)
                                

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

    return plaintext.decode()

def generate_key(key_size=32):
    return get_random_bytes(key_size)

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

        # Add encrypted data to email & remove nounce 
        if count == 0:
           encrypted_email += encrypted_chunk[AES.block_size:]
           count += 1

        else:
            encrypted_email += encrypted_chunk

        # check if entire message has been received
        try:
            #print(encrypted_email)
            decrypted_email = cipher.decrypt(encrypted_email).decode()
            if "END_OF_EMAIL" in decrypted_email:
                email = decrypted_email.split("END_OF_EMAIL")[0]
                break
        except ():
            # continue receiving more data if message is incomplete
            continue
    # in case loop exits without returning (it shouldn't in normal conditions)
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

def store_emails(users,title,email,sender):
    for user in users:
        dir = os.path.dirname(os.path.abspath(__file__))
        filename = f'{user}/{sender}_{title.replace(" ","_")}.txt'
        with open(os.path.join(dir,filename), 'w') as email_file:
            email_file.write(email)

 # call the server function below
if __name__ == "__main__":
    server()