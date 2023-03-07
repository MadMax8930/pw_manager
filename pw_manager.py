# Exercice just to practice, all pwds must be stored in secure databases!!
# Module: pip3 install cryptography

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

while True:
    master_pwd = input("\n 🔓 What is the master password? 🔒 \n")
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    master_key_hash = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode())) #in bytes
    fernetObject = Fernet(master_key_hash)
    tokenEncryption = fernetObject.encrypt(master_pwd.encode())
    tokenDecryption = fernetObject.decrypt(tokenEncryption).decode()

    ######

    '''
    def write_key():
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)'''

    def load_key():
        file = open("key.key", "rb")
        key = file.read()
        file.close()
        return key

    key = load_key()
    fer = Fernet(key)

    def view():
        with open('passwords.txt', 'r') as f:
            for line in f.readlines():
                data = line.rstrip()
                user, passw = data.split("|")
                print("User:", user, ", Password:", fer.decrypt(passw.encode()).decode())

    def add():
        name = input("\n 🧬 Account Name: ")
        pwd = input(" 🔑 Password: ")
        print("\n ✅ User has been added to the passwords.txt file ✅ ")

        with open('passwords.txt', 'a') as f:
            f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "\n")

    ######

    if tokenDecryption == "check":
        print("\n 🔥 Access granted! Welcome friend! 🔥 ")
        while True:
            mode = input("\n ⭐ Would you like to add a new password (ADD) or view existing ones (VIEW)? Type (Q) to quit ⭐ \n").lower()
            if mode == "q":
                break

            if mode == "view":
                view()
            elif mode == "add":
                add()
            else:
                print("\n 🚧 Ivalid mode. 🚧 \n")
                continue
    else:
        print("\n ⛔ Enter the correct master password ⛔")
    continue