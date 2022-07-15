from cryptography.hazmat.primitives.asymmetric import dh


def public_key(private_key):
    pub_key = private_key.public_key()
    return pub_key


def shared_key(private_key, pub_key):
    return private_key.exchange(pub_key)


class DiffieHellman:

    def __init__(self):
        self.params = dh.generate_parameters(2, 2048)

    def private_key(self):
        private_key = self.params.generate_private_key()
        return private_key
