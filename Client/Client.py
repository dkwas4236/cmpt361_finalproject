# Client.py
import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

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

        # grab the users private key by taking their username
        client_private_key_file = os.path.join(dir,'%s_private.pem' % username)
        with open(client_private_key_file, 'rb') as file:
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
        menu = clientSocket.recv(2048)
        if menu.endswith(b'FAILED'):
            print(menu)
            clientSocket.close()
            sys.exit(1)
        else:
            cipher = AES.new(sym_key, AES.MODE_ECB)
            menu = unpad(cipher.decrypt(menu), AES.block_size).decode()

        # Loop until user termination
        while(1):
            # Display menu and get user choice
            choice = input(menu)
            # Send choice to server
            encrypt(choice, clientSocket, sym_key)
            if choice == "1":
                # get email prompt 
                emailPrompt = decrypt(clientSocket,sym_key)
                if emailPrompt == "Send the email":
                    # Get destinations from user 
                    destinations = input("Enter destinations (seperated by;): ")
                    # Get title from user
                    title = input("Enter Title: ")
                    # Does the user want to attach a file to the email?
                    fileAttached = input("Would you like to load contents from a file?(Y/N) ")
                    if (fileAttached.strip() == 'N' or fileAttached.strip() == 'n'):
                        # Contentes recieved from command line 
                        print("Enter Message Contents: ")
                        contents = input()
                    else:
                        filename = input("Enter filename: ")
                        with open(os.path.join(dir,filename),'r') as file:
                            contents = file.read()

                    email = create_email(username,destinations,title,contents)
                    send_email(email, clientSocket, sym_key, username, destinations)

    
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
                view_sent_email_info(index, clientSocket, sym_key)
                
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
    try:
        # receive data from the socket
        encrypted_data = socket.recv(2048)

        # check if the received data is empty
        if not encrypted_data:
            raise ValueError("Empty or no data received")

        # decrypt the data
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return plaintext.decode()
    
    except ValueError as ve:
        print("Error:", ve)
        return ""
    
    except Exception as e:
        print("An error occurred during decryption:", e)
        return ""


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

def send_email(email, socket, key, username, destinations):
    cipher = AES.new(key, AES.MODE_ECB)
    # encrypt and send email
    email = email.encode('ascii')
    email_chunks = [email[i:i + AES.block_size] for i in range(0, len(email), AES.block_size)]
    for chunk in email_chunks:
        cipher_chunk = cipher.encrypt(pad(chunk, AES.block_size))
        socket.send(cipher_chunk)
    # Send end of email flag
    cipher_finished = cipher.encrypt(pad(b'END_OF_EMAIL', AES.block_size))
    socket.send(cipher_finished)

    # Save email to client directories
    save_email_to_client(email, username, destinations)

def save_email_to_client(email, username, destinations):
    # Create a directory for the current user if it doesn't exist
    user_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"client{username}")
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

    # Split destinations and create a text file for each destination
    dest_list = destinations.split(";")
    for dest in dest_list:
        dest_dir = os.path.join(user_dir, dest.strip())
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        # Decode email from bytes to string
        email_str = email.decode('utf-8')

        # Extract title from email string
        email_lines = email_str.split('\n')
        title = ""
        for line in email_lines:
            if line.startswith("Title:"):
                title = line.split("Title:")[1].strip()
                break

        # Create a file with source client username and email title
        email_filename = f"{username}_{title.replace(' ', '_')}.txt"
        email_path = os.path.join(dest_dir, email_filename)

        with open(email_path, 'w') as email_file:
            email_file.write(email_str)

    print("Emails saved successfully to client directories.")




def view_sent_email_info(index, socket, key):
    send_email(index, socket, key)

    encrypted_info = socket.recv(2048)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(encrypted_info), AES.block_size)
    print(plaintext.decode())


# call the client function below
if __name__ == "__main__":
    client()
