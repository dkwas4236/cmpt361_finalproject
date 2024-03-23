# Client.py
import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

def client():
    serverPort = 13000

    # Create cloent socket using IPv4 and TCP protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)
    
    try:
        # Get IP or Server name from user
        serverName = input('Enter the server IP or name: ') 
        # Client conncets with the server
        clientSocket.connect((serverName, serverPort))

        # Client receives the initial username message
        usernameReq = clientSocket.recv(2048).decode('ascii') 
        username = input(usernameReq)
        # Send username back to server 
        clientSocket.send(username.encode('ascii'))

        # Recive menu from server
        menu = clientSocket.recv(2048).decode('ascii')
        
        # Loop until user termination
        while(1):
            # Display menu and get user chice 
            choice = input(menu)
            # Send choice to server
            clientSocket.send(choice.encode('ascii'))
            if choice == "1":
                # Receive destination promt from the server and get user input
                destinationReq = clientSocket.recv(2048).decode('ascii')
                destinations = input(destinationReq)
                # Send destination(s) to the server 
                clientSocket.send(destinations.encode('ascii'))

                # Receive title request from the server 
                titleReq = clientSocket.recv(2048).decode('ascii')
                choice = input(titleReq)
                # Get title from user and send back to server 
                clientSocket.send(choice.encode('ascii'))

                # Receive load file request from the server
                loadFromFileReq = clientSocket.recv(2048).decode('ascii')
                choice = input(loadFromFileReq)
                # Send user input back to server
                clientSocket.send(choice.encode('ascii'))
                
                # Get message content prompt from the server
                contentsReq = clientSocket.recv(2048)
                print(contentsReq.decode('ascii'))
                # Send content back to the server
                content = input()
                clientSocket.send(content.encode('ascii'))

            elif choice == "2":
                # Receive inbox list from server 
                inboxlist = clientSocket.recv(2048).decode('ascii')
                print(inboxlist)

            elif choice == "3":
                # Get message from server and get index from user
                index_prompt = clientSocket.recv(2048).decode('ascii')
                #print(f'{index_prompt}{input()}')
                index = input(index_prompt)
                # Send index back to the server 
                clientSocket.send(index.encode('ascii'))
                
            elif choice == "4":
                # Client terminates connection with the server 
                print("Connection Terminated")
                clientSocket.close()
                sys.exit(1)
    
        
        '''else:
            message = clientSocket.recv(2048)
            print(message.decode('ascii'))'''
         

    except socket.error as e:
        print('An error occurred:', e)
        sys.exit(1)

# call the client function below
if __name__ == "__main__":
    client()
