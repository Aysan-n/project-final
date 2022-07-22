import socket
import threading
import time
import json
from Authentication import authentication
from Registration import receive_registration
from server.Command_handler import server_command_handler


def serialize(message):
    return json.dumps(message).encode()


def deserialize(message):
    return json.loads(message.decode())


class Messaging:

    def __init__(self, private_key):
        self.socket = None
        self.reqs = []
        self.connections = []
        self.private_key = private_key

    def create_socket(self, port):
        self.socket = socket.socket()
        print("Server socket created")
        self.socket.bind(('localhost', port))

    def start_receiving(self):
        self.socket.listen()
        print("Server is listening")

        while True:
            c, addr = self.socket.accept()
            message = c.recv(2048)
            message = deserialize(message)
            print(message)
            self.reqs.append(message)
            self.connections.append(c)
            # print("appended")

    def send_message(self, message, c):
        print(message)
        c.send(serialize(message))

    def handle_registration(self, connection, request):
        receive_registration(self, connection, request, self.private_key)

    def handle(self, request, connection):
        if request['message_type'] == 'registration':
            self.handle_registration(connection, request)
            try:
                message = connection.recv(2048)
                if message != ''.encode():
                    message = deserialize(message)
                    print(message)
                    self.reqs.append(message)
                    self.connections.append(connection)
                else:
                    connection.close()
            except:
                pass

        elif request['message_type'] == 'authentication':
            authentication(self, connection)
            message = connection.recv(2048)
            if message != ''.encode():
                message = deserialize(message)
                print(message)
                self.reqs.append(message)
                self.connections.append(connection)
            else:
                connection.close()

        elif request['message_type'] == 'client_command':
            server_command_handler(self, connection, request)
            message = connection.recv(2048)
            if message != ''.encode():
                message = deserialize(message)
                print(message)
                self.reqs.append(message)
                self.connections.append(connection)
            else:
                connection.close()
        else:
            print("ERROR")

    def handle_tasks(self):
        while True:
            if len(self.reqs) != 0:
                request = self.reqs.pop()
                connection = self.connections.pop()
                self.handle(request, connection)
            else:
                # print(len(self.reqs))
                time.sleep(2)

    def start(self):
        thread = threading.Thread(target=self.start_receiving, args=())
        thread.start()
        self.handle_tasks()


def serialize(message):
    return json.dumps(message).encode()


def deserialize(message):
    return json.loads(message.decode())
