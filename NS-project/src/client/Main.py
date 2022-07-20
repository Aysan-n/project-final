import time

from rsa import PublicKey

from Command_handler import command_handler
from Authentication import client_auth
from Messaging import Messaging
from Registration import initiate_registration
import os
import rsa



# public_key = PublicKey(
#     94057119611095946281523367855001930801008421995257743937642282436572904657606798603159545412659607974565461332313984750403479192213716994833909001676613969160857359369527054950459340417810569591327134941274724766743027563401125940872842341580457651667285658979777888792614809061606256624792008312706379659423,
#     65537)


with open(os.getcwd()+"/NS-project/src/client/public_key.pem") as file:
    data = file.read()
public_key = rsa.PublicKey.load_pkcs1_openssl_pem(data)

messaging = Messaging()
messaging.create_socket(2051)

seq_number = None
session_key = None

while True:
    action = input()
    if action == "register":
        first_name = input("Input your first name:")
        last_name = input("Input your last name:")
        username = input("Input your username:")
        password = input("Input your password:")
        initiate_registration(messaging, public_key, first_name, last_name, username, password)
    elif action == "authentication":
        username = input("Input your username:")
        password = input("Input your password:")
        seq_number, session_key = client_auth(messaging, public_key, username, password)
        seq_number = seq_number+1
    elif action == "command":

        if seq_number is not None and session_key is not None:
            username = input("Input your username:")
            command = input("Input command:")
            command_handler(messaging, command, seq_number, session_key, username)
            message = messaging.receive()
            #print(message)
            if message["status"] == "ok":
                #print("okay")
                message = messaging.receive()
                print(message["status"])
                seq_number = seq_number+1
        else:
            print("Not authenticated yet.")
    else:
        print("Invalid command.")

# command_handler(messaging, 'mkdir /very6', seq_number, session_key, "Ays")





