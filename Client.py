# client.py
import socket
import json
import os
import sys

def client():
    serverName = '127.0.0.1' 
    serverPort = 13000

    while True:
        try:
            clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error as e:
            print('Error in client socket creation:', e)
            sys.exit(1)

        try:
            clientSocket.connect((serverName, serverPort))

            usernameReq = clientSocket.recv(2048)  # client receives the initial username message
            print(usernameReq.decode('ascii')) 

            username = input()
            clientSocket.send(username.encode('ascii'))

            # client response to server from 1
            if username == "user1":
                optionReq = clientSocket.recv(2048)
                print(optionReq.decode('ascii'))
                choice = input()
                clientSocket.send(choice.encode('ascii'))

                if choice == "1":
                    destinationReq = clientSocket.recv(2048)
                    print(destinationReq.decode('ascii'))
                    choice = input()
                    clientSocket.send(choice.encode('ascii'))

                    titleReq = clientSocket.recv(2048)
                    print(titleReq.decode('ascii'))
                    choice = input()
                    clientSocket.send(choice.encode('ascii'))

                    loadFromFileReq = clientSocket.recv(2048)
                    print(loadFromFileReq.decode('ascii'))
                    choice = input()
                    clientSocket.send(choice.encode('ascii'))

                    contentsReq = clientSocket.recv(2048)
                    print(contentsReq.decode('ascii'))
                    choice = input()
                    clientSocket.send(choice.encode('ascii'))

                elif choice == "2":
                    completion_message = clientSocket.recv(2048)
                    print(completion_message.decode('ascii'))

                elif choice == "3":
                    completion_message = clientSocket.recv(2048)
                    print(completion_message.decode('ascii'))
                    choice = input()
                    clientSocket.send(choice.encode('ascii'))
                    
                else:
                    break
            else:
                message = clientSocket.recv(2048)
                print(message.decode('ascii'))
                break  

            # client terminates connection with the server 
            clientSocket.close()

        except socket.error as e:
            print('An error occurred:', e)
            sys.exit(1)

# call the client function below
if __name__ == "__main__":
    client()
