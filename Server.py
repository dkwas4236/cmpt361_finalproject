# server.py
import socket
import sys
import json
import os

def server():
    serverPort = 13000
    welcome = 0

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

            if welcome == 0:
                welcomeMessage = ("\nEnter your username: ")

            connectionSocket.send(welcomeMessage.encode('ascii'))
            welcome = 1

            message = connectionSocket.recv(2048)
            decodedMessage = message.decode('ascii') # decode the username

            if decodedMessage == "user1": # TODO accept only certain users
                menuMessage = ("\n\nSelect the operation:\n1)Create and send an email\n2)Display the inbox list\n3)Display te email contents\n4)Terminate the connection\n\nChoice:")
                connectionSocket.send(menuMessage.encode('ascii'))

                clientChoice = connectionSocket.recv(2048)
                decodedChoice = clientChoice.decode('ascii')

                if decodedChoice == "1":
                    # show file info
                    destination = "Enter destinations(seperated by;):"
                    connectionSocket.send(destination.encode('ascii'))
                    clientChoice = connectionSocket.recv(2048)
                    decodedChoice = clientChoice.decode('ascii')
                    
                    title = "Enter title: "
                    connectionSocket.send(title.encode('ascii'))
                    clientChoice = connectionSocket.recv(2048)
                    decodedChoice = clientChoice.decode('ascii')

                    loadFile= "Would you like to load contents from a file?(Y/N)"
                    connectionSocket.send(loadFile.encode('ascii'))
                    clientChoice = connectionSocket.recv(2048)
                    decodedChoice = clientChoice.decode('ascii')

                    contents = "Enter message contents: "
                    connectionSocket.send(contents.encode('ascii'))
                    clientChoice = connectionSocket.recv(2048)
                    decodedChoice = clientChoice.decode('ascii')

                elif decodedChoice == "2":
                    # display file data
                    completion_message = "Inbox List Info Displayed"
                    connectionSocket.send(completion_message.encode('ascii'))

                elif decodedChoice == "3":
                    response = 'Enter the email index you wish to view: '
                    connectionSocket.send(response.encode('ascii'))
                    clientChoice = connectionSocket.recv(2048)
                    decodedChoice = clientChoice.decode('ascii')

                elif decodedChoice == "4":
                    #terminate connection
                    break
                else:
                    print("Invalid choice.")

            else:
                terminationMessage = "Incorrect username. Connection Terminated"
                connectionSocket.send(terminationMessage.encode('ascii'))
                connectionSocket.close()
                serverSocket.close()
                sys.exit(1)

        except socket.error as e:
            print('An error occurred:', e)
            serverSocket.close()
            sys.exit(1)
        except Exception as e:
            print('An unexpected error occurred:', e)
            serverSocket.close()
            sys.exit(1)

# call the server function below
if __name__ == "__main__":
    server()

