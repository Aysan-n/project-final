from time import time

import rsa
from Crypto.Random import get_random_bytes
import hashlib

from File_Decryption import seq_Decryption


def client_auth(messaging, public_key, client_user_name: str, client_pwd: bytes):
    client_message = {'message_type': 'authentication'}
    ###############################    بر اساس پیام دریافتی
    messaging.send_message(client_message)

    # server_message = Client_message_receiver()

    server_message = messaging.receive()
    print(server_message)
    server_nance = bytes.fromhex(server_message['server_nance'])
    hash_string = (hashlib.sha1(server_nance + client_pwd.encode())).hexdigest()  # string
    session_key = get_random_bytes(16)

    ################### عملیات دریافت کلید عمومی، و رمز کردن کلید جلسه
    ########################

    enc_string = rsa.encrypt(session_key, public_key).hex()

    client_message = {'message_type': 'authentication', 'client_user_name': client_user_name,
                      'hash_string': hash_string, 'enc_str': enc_string}  ###### نیاز به کامل شدن

    messaging.send_message(client_message)
    # Client_message_sender(client_message)
    # server_message = Client_message_receiver()
    server_message = messaging.receive()

    if server_message['status'] != 'error':
        enc_string = bytes.fromhex(server_message['enc_str'])
        seq_number = seq_Decryption(enc_string, session_key)
        ############# عملیات رمز گشایی و بدست آوردن seq num
        hash_string = (hashlib.sha1(client_pwd.encode() + seq_number.to_bytes(2, 'big'))).hexdigest()
        if hash_string == server_message['hash_string']:
            print("Authenticated successfully.")
            return seq_number, session_key
        else:
            print("Authentication failed.")
            return False
    else:
        print("Authentication failed.")
        return False

