# key_generator.py
import os
from Crypto.PublicKey import RSA

# Generates an RSA key
# key size = 1024 bytes (should be enough bytes; if not can change)
def generate_key(key_size=1024):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key

# Save a key to file
def save_key(key, filename, directory=""):
    if directory:
        filename = os.path.join(directory, filename)
    with open(filename, 'wb') as key_file:
        key_file.write(key)

# generates the keys and saves them to specified files
# also generates the .pem files in the required directories
def generate_save_keys(usernames, key_size=1024):
    # server keys
    server_public, server_private = generate_key(key_size)
    ensure_directory_exists('Server')
    save_key(server_private, 'server_private.pem', directory='Server')
    save_key(server_public, 'server_public.pem', directory='Server')
    save_key(server_public, 'server_public.pem', directory='Client')

    # client keys
    for username in usernames:
        client_public, client_private = generate_key(key_size)
        ensure_directory_exists(os.path.join('Client'))
        save_key(client_private, '%s_private.pem' % username, directory='Client')
        save_key(client_public, '%s_public.pem' % username, directory='Client')
        save_key(client_public, '%s_public.pem' % username, directory='Server')
        # creates directories to store emails
        dir = os.path.dirname(os.path.abspath(__file__))
        ensure_directory_exists(os.path.join(dir,'Server/%s' % username))


# ensures the directory exists, creates it if it doesn't
def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        print(f"creating directory {directory}")
        os.makedirs(directory)

client_usernames = ['client1', 'client2', 'client3', 'client4', 'client5']

# generate the keys and save them to the files
generate_save_keys(client_usernames)
