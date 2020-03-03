"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Gunther Wallach


"""

import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP

file = open("public.pem", "rb")
public_key = RSA.importKey(file.read())

host = "localhost"

port = 10001

# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    return os.urandom(16)

# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    return public_key.encrypt(session_key,0)[0]


def decrypt_message(client_message, session_key):
    #decrypt the message with the session key
    iv = enc_msg[:AES.block_size]
    cipher_AES = AES.new(session_key, AES.MODE_EAX, iv)
    message = cipher_AES.decrypt(client_message)
    return message
    
    
# Encrypt a message using the session key
def encrypt_message(message, session_key):
    #access public key
    #encrypt message with AES session key
    cipher_AES = AES.new(session_key,AES.MODE_EAX)
    cipher_message = cipher_AES.encrypt(message)
    return cipher_message


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server DONE
        encrypted_message  = encrypt_message(message,encrypted_key)
        send_message(sock,encrypted_message)
        
        # TODO: Receive and decrypt response from server DONE
        encrypted_response = receive_message(sock)
        response = decrypt_message(encrypted_response, key)
        print(response)
        
    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
