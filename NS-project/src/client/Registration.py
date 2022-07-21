import rsa


def initiate_registration(messaging, pub_key, first_name, last_name, username, password, key):
    cipher = rsa.encrypt(build_message(first_name, last_name, username, password).encode(), pub_key).hex()
    messaging.send_message({'message_type': 'registration', 'cipher': cipher, 'key':key})
    reply = messaging.receive()
    print(reply)
    if reply['status'] == 'failed':
        print("Registration failed. Try again!")
    else:
        print("Registration successful.")


def build_message(first_name, last_name, username, password):
    return first_name + " " + last_name + " " + username + " " + password
