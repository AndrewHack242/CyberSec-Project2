"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Gunther Wallach



"""

import socket
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

key = RSA.generate(2048)
#generate private key
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)

#generate public key
public_key = key.publickey().export_key()
file_out = open("public.pem", "wb")
file_out.write(public_key)

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    return private_key.decrpyt(session_key)


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key, nonce, tag):
    #input file for encrypted message
    private_key = RSA.importKey(open("private.pem").read())
    #decrypt sessions key with the private RSA key
    cipher_RSA = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(session_key)
    #decrypt the message with the session key
    cipher_AES = AES.new(session_key, AES.MODE_EAX, nonce)
    message = cipher_AES.decrypt_and_verify(client_message, tag)
    return message
    
    


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    #access public key
    public_key = RSA.import_key(open("public.pem").read())
    #encrypt session key with the public RSA key
    cipher_RSA = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_RSA.encrypt(session_key)
    #encrypt message with AES session key
    cipher_AES = AES.new(session_key,AES.MODE_EAX)
    cipher_message, tag = cipher_AES.encrypt_and_digest(message)
    return encrypted_session_key, cipher_aes.nonce, tag, encrypt_message

# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # TODO: Generate the hashed password DONE
                p = hashlib.sha3_512()
                p.update(password.encode())
                hashed_password = p.digest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                message = decrypt_message(ciphertext_message,plaintext_key)
                
                # TODO: Split response from user into the username and password
                user = message.split(' ')[0]
                password = message.split(' ')[1]
                verified = verify_hash(user,password)
                # TODO: Encrypt response to client
                response = ""
                if(verified):
                    response = "Verification Successful!"
                else:
                    response = "Verification Failed"
                ciphertext_response = encrypt_message(response,plaintext_key)
                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
