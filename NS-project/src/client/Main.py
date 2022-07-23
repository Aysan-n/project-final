import time
from os.path import exists

from Crypto.PublicKey import RSA
from rsa import PublicKey

from Command_handler import command_handler
from Authentication import client_auth
from Messaging import Messaging
from Registration import initiate_registration
import os
import rsa

from key_managemnt_table import find_decrypted


def decrypt_ls(result):
    # print(result)
    return result
    try:
        result = result.split("\n")
        final = ""
        for text in result:
            #print(text)
            if text != "":
                if text[0:5] == "total":
                    final = final + text + "\n"
                else:
                    last_index = text.rindex(" ")
                    # print(last_index)
                    enc_file = text[last_index + 1:]
                    # print(enc_file)
                    beginning = text[0:last_index + 1]
                    if enc_file != "Shared_file":
                        if ".txt" not in enc_file:
                            name = find_decrypted(enc_file)[0]
                        else:
                            enc_file = enc_file[0: enc_file.rindex(".")]
                            name = find_decrypted(enc_file)[0]+".txt"
                    else:
                        name = "Shared_file"
                    final = final + beginning + name + "\n"
        return final
    except:
        return result




def decrypt_cd(result):
    error = result

    result = result[1:]
    # try:
    result = result.split("/")
    final = ""
    try:
        for file in result:
            name = find_decrypted(file)[0]
            final = final + "/" + name
        print(final)
    except:
        print(error)


def create_key():
    if not exists("Aysan_private.txt"):
        new_key = RSA.generate(2048)
        key = new_key.exportKey("PEM")
        f1 = open("Aysan_private.txt", "a")
        f1.write(key.hex())
        f2 = open("Aysan_public.txt", "a")
        f2.write(new_key.public_key().exportKey("PEM").hex())
        print("Written public key")

    f1 = open("Aysan_private.txt", "r")
    key_data = bytes.fromhex(f1.read())
    private_key = rsa.PrivateKey.load_pkcs1(key_data, 'PEM')
    f1.close()
    f2 = open("Aysan_public.txt", "r")
    key_data = bytes.fromhex(f2.read())
    # public_key = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)
    f2.close()
    return private_key, key_data


with open(os.getcwd() + "/src/client/public_key.pem") as file:
    data = file.read()
public_key = rsa.PublicKey.load_pkcs1_openssl_pem(data)

messaging = Messaging()
messaging.create_socket(2050)

seq_number = None
session_key = None

my_key, my_public_key = create_key()

while True:
    action = input("Press\n"
                   "1 for REGISTRATION\n"
                   "2 for AUTHENTICATION\n"
                   "3 for COMMAND\n")
    if action == "1":
        first_name = input("Input your first name:")
        last_name = input("Input your last name:")
        username = input("Input your username:")
        password = input("Input your password:")
        initiate_registration(messaging, public_key, first_name, last_name, username, password, my_public_key.hex())
    elif action == "2":
        username = input("Input your username:")
        password = input("Input your password:")
        seq_number, session_key = client_auth(messaging, public_key, username, password)
        seq_number = seq_number + 1
    elif action == "3":

        if seq_number is not None and session_key is not None:
            username = input("Input your username:")
            command = input("Input command:")
            command_handler(messaging, command, seq_number, session_key, username)
            message = messaging.receive()
            print(message)
            if message["status"] == "ok":
                # print("okay")
                message = messaging.receive()
                if command[0:2] != 'cd' or ("Shared_file" in command):
                    if command[0:2] != 'ls':
                        print(message["status"])
                    else:
                        print(decrypt_ls(message["status"]))
                else:
                    decrypt_cd(message["status"])
                seq_number = seq_number + 1
        else:
            print("Not authenticated yet.")
    else:
        print("Invalid command.")

# command_handler(messaging, 'mkdir /very6', seq_number, session_key, "Ays")
