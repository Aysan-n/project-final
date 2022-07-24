import platform
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


def decrypt_ls_linux(result):
    # print(result)
    try:
        result = result.split("\n")
        final = ""
        for text in result:
            # print(text)
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
                            name = find_decrypted(username,enc_file)[0]
                        else:
                            enc_file = enc_file[0: enc_file.rindex(".")]
                            name = find_decrypted(username,enc_file)[0] + ".txt"
                    else:
                        name = "Shared_file"
                    final = final + beginning + name + "\n"
        return final
    except:
        return '\n'.join(result)


def decrypt_ls_windows(result):
    try:
        result = result.split("\n")
        final = ""
        for text in result:
        # print(text)
            if text != "":
                if text[0:5] == "total" or text[0] == " ":
                    final = final + text + "\n"
                else:
                    last_index = text.rindex(" ")
                # print(last_index)
                    enc_file = text[last_index + 1:]
                    enc_file = enc_file[0:enc_file.index("\r")]
                # print('***********encfile',enc_file)
                    beginning = text[0:last_index + 1]
                    if enc_file != "Shared_file" and enc_file[0] != "." and enc_file[0] != "..":
                        if ".txt" not in enc_file:
                           name = find_decrypted(username,enc_file)[0]
                        else:
                           enc_file = enc_file[0: enc_file.rindex(".")]
                           name = find_decrypted(username,enc_file)[0] + ".txt"
                    else:
                        name = enc_file
                    final = final + beginning + name + "\n"
        return final
    except:
        return '\n'.join(result)


# except:
#     return result


def decrypt_ls(result):
    operating_system = platform.system()
    if operating_system == "Windows":
        return decrypt_ls_windows(result)
    else:
        return decrypt_ls_linux(result)


def decrypt_cd(user,result):
    error = result
    result = result[1:]
    # try:
    result = result.split("/")
    final = ""
    try:
        for file in result:
            name = find_decrypted(user,file)[0]
            final = final + "/" + name
        print(final)
        
        return final
    except:
        return result


def create_key(user):
    if not exists(user + "_private.txt"):
        new_key = RSA.generate(2048)
        key = new_key.exportKey("PEM")
        f1 = open(user + "_private.txt", "a")
        f1.write(key.hex())
        f2 = open(user + "_public.txt", "a")
        f2.write(new_key.public_key().exportKey("PEM").hex())
        print("Written public key")

    f1 = open(user + "_private.txt", "r")
    key_data = bytes.fromhex(f1.read())
    private_key = rsa.PrivateKey.load_pkcs1(key_data, 'PEM')
    f1.close()
    f2 = open(user + "_public.txt", "r")
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



while True:
    action = input("Press\n"
                   "1 for REGISTRATION\n"
                   "2 for AUTHENTICATION\n"
                   "3 for COMMAND\n")
    if action == "1":
        first_name = input("Input your first name:")
        last_name = input("Input your last name:")
        user_name= input("Input your username:")
        password = input("Input your password:")
        my_key, my_public_key = create_key(user_name)
        initiate_registration(messaging, public_key, first_name, last_name, user_name, password, my_public_key.hex())
    elif action == "2":
        username = input("Input your username:")
        password = input("Input your password:")
        seq_number, session_key = client_auth(messaging, public_key, username, password)
        seq_number = seq_number + 1
        cwd='/'
    elif action == "3":
        if seq_number is not None and session_key is not None:
            command = input("Input command:")
            print('cwd**********',cwd)
            command_handler(username, messaging, command, seq_number, session_key, username,cwd)
            message = messaging.receive()
            print(message)
            if message["status"] == "ok":
                # print("okay")
                message = messaging.receive()
                if command[0:2] != 'cd':
                    if command[0:2] != 'ls':
                        print(message["status"])
                    else:
                        print(decrypt_ls(message["status"]))
                else:
                    cwd=decrypt_cd(username, message["status"])
                seq_number = seq_number + 1
        else:
            print("Not authenticated yet.")
    else:
        print("Invalid command.")

# command_handler(messaging, 'mkdir /very6', seq_number, session_key, "Ays")
