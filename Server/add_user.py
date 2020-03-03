"""
    add_user.py - Stores a new username along with salt/password

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    The solution contains the same number of lines (plus imports)
"""

import hashlib
import string
from random import randint
import random

#print(hashlib.algorithms_available)
#print(hashlib.algorithms_guaranteed)

p = hashlib.sha3_512()

user = input("Enter a username: ")
password = input("Enter a password: ")

# TODO: Create a salt and hash the password DONE
letters = string.ascii_lowercase + string.ascii_uppercase + string.digits
salt = ""
n = randint(4,7)
for i in range(0,n):
    salt = salt + random.choice(letters)
password = password + salt
p.update(password.encode())
hashed_password = p.digest()

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")
