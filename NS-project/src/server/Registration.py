import rsa
import random
import os

from Client_table import add_client, table_contains_client


def receive_registration(messaging, connection, message, private_key):
    if message['message_type'] != 'registration':
        print("Error in registration")
        server_message = {'message_type': 'registration', 'status': 'failed'}
        messaging.send_message(server_message, connection)
        return
    else:
        user_public_key = message["key"]
        message = message['cipher']
        message = bytes.fromhex(message)
        message = rsa.decrypt(message, private_key).decode()
        messages = str.split(message)
        if table_contains_client(messages[2]):
            server_message = {'message_type': 'registration', 'status': 'failed'}
            messaging.send_message(server_message, connection)
        else:
            print(messages[0], messages[1], messages[2], messages[3])
            enc_username = 'U'+'%d' %random.randint(1000,100000000)
            os.makedirs(os.getcwd()+"/NS-project/src/server/Repository/"+'%s' %enc_username)
            os.makedirs(os.getcwd()+"/NS-project/src/server/Repository/"+'%s' %enc_username + '/Shared_file')
            add_client(messages[0], messages[1], messages[2], messages[3], enc_username, user_public_key)    ########## این قسمت باید درست شود
            server_message = {'message_type': 'registration', 'status': 'ok'}
            messaging.send_message(server_message, connection)
