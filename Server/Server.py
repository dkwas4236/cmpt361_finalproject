# Server.py
import socket, sys, os, glob, datetime, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

def server():
    serverPort = 13000
    welcome = 0

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
                    welcomeMessage = ("Enter your username: ")
                    connectionSocket.send(welcomeMessage.encode('ascii'))

                    # Receive Username
                    username = connectionSocket.recv(2048).decode('ascii')

                    if username == "user1": # TODO accept only certain users
                        # Create menu prompts and sent to the client
                        menuMessage = ("\nSelect the operation:\n\t1) Create and send an email\n\t2) Display the inbox list\n\t3) Display the email contents\n\t4)Terminate the connection\nChoice: ")
                        connectionSocket.send(menuMessage.encode('ascii'))

                        while (1):
                            # Receive user chice from client 
                            clientChoice = connectionSocket.recv(2048)
                            decodedChoice = clientChoice.decode('ascii')

                            if decodedChoice == "1":
                                # Send destination prompt to the client 
                                destination = "Enter destinations (seperated by;): "
                                connectionSocket.send(destination.encode('ascii'))
                                # Receive the destinations from the client 
                                destination = connectionSocket.recv(2048).decode('ascii')
                                print(destination)
                    
                                # Send title prompt to the user 
                                title = "Enter title: "
                                connectionSocket.send(title.encode('ascii'))
                                # receive title from the client
                                title = connectionSocket.recv(2048).decode('ascii')
                                print(title)

                                # Send loadFile prompt to the user
                                loadFile= "Would you like to load contents from a file?(Y/N)"
                                connectionSocket.send(loadFile.encode('ascii'))
                                # Receive response from user
                                loadFile = connectionSocket.recv(2048).decode('ascii')
                                print(loadFile)

                                # Send content prompt to the user
                                contents = "Enter message contents: "
                                connectionSocket.send(contents.encode('ascii'))
                                # Receive content from the client 
                                content = connectionSocket.recv(2048).decode('ascii')
                                print(content)

                            elif decodedChoice == "2":
                                # Get inbox list and send to server
                                inboxlist = "Inbox List Info Displayed"
                                connectionSocket.send(inboxlist.encode('ascii'))

                            elif decodedChoice == "3":
                                # Send prompt to server
                                response = "Enter the email index you wish to view: "
                                connectionSocket.send(response.encode('ascii'))
                                # Receive index from user
                                index = connectionSocket.recv(2048).decode('ascii')
                                print(index)

                            elif decodedChoice == "4":
                                #terminate connection
                                connectionSocket.close()
                                sys.exit(1)

                            else:
                                print("Invalid choice.")

                    else:
                        terminationMessage = "Incorrect username. Connection Terminated"
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

# call the server function below
if __name__ == "__main__":
    server()

