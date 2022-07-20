import socket
import json


class Messaging:

    def __init__(self):
        self.socket = None

    def create_socket(self, port):
        self.socket = socket.socket()
        print("Client socket created")
        self.socket.connect(('localhost', port))

    def send_message(self, message):
        self.socket.send(serialize(message))

    def receive(self):
        message = self.socket.recv(2048)
        message = deserialize(message)
        return message


def serialize(message):
    return json.dumps(message).encode()


def deserialize(message):
    return json.loads(message.decode())
