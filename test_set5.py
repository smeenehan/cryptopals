from hashlib import sha1
from unittest import TestCase

from Crypto.Cipher import AES

import crypto.hash as ch
import crypto.key_exchange as ck
import crypto.utils as cu

class BobServer(object):
    """Mock up a server where Bob can do Diffie-Hellman key-exchange, and
    use this to echo back encrypted messages using the shared secret."""

    def __init__(self):
        self.private, self.public = 0, 0
        self.secret = bytes([])

    def key_exchange(self, p, g, public):
        self.private, self.public = ck.gen_DH_keys()
        self.secret = ck.gen_DH_secret(self.private, public)
        return self.public

    def echo(self, cipher, iv):
        key = cbc_keygen(self.secret)
        aes = AES.new(key, AES.MODE_CBC, iv)
        plain = aes.decrypt(cipher)

        iv = cu.random_bytes()
        aes = AES.new(key, AES.MODE_CBC, iv)
        return aes.encrypt(plain), iv

class EveServer(object):
    """Mock up a server where Eve acts as a MITM between Alice and Bob
    (the latter using the BobServer object).

    We will use parameter injection to break Diffie-Hellman by ensuring
    that the secret is always 0 (empty byte-string)"""

    def __init__(self, server):
        self.server = server
        self.key = cbc_keygen(bytes([]))
        self.last_client_msg = bytes([])
        self.last_server_mas = bytes([])

    def key_exchange(self, p, g, public):
        self.server.key_exchange(p, g, p)
        return p

    def echo(self, cipher, iv):
        """Pass through client and server messages, while decrypting and
        storing each"""
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        self.last_client_msg = aes.decrypt(cipher)

        cipher_server, iv_server = self.server.echo(cipher, iv)
        aes = AES.new(self.key, AES.MODE_CBC, iv_server)
        self.last_server_msg = aes.decrypt(cipher_server)
        return cipher_server, iv_server


def cbc_keygen(secret):
    m = sha1()
    m.update(secret)
    return m.digest()[:AES.block_size]

class Set5(TestCase):

    def test_DH_echo(self):
        server = BobServer()

        """Alice generates DH parameters, sends to Bob, generates shared
        secret according to Diffie-Hellman"""
        p, g = ck.DH_P, ck.DH_G
        private, public = ck.gen_DH_keys()
        public_server = server.key_exchange(p, g, public)
        secret = ck.gen_DH_secret(private, public_server)

        """Use secret to encrypt a random message, send to Bob, and get
        his ciphertext. Verify that it encrypts the same plaintext."""
        iv = cu.random_bytes()
        key = cbc_keygen(secret)
        aes = AES.new(key, AES.MODE_CBC, iv)
        plain = cu.random_bytes(count=256)
        cipher = aes.encrypt(plain)
        cipher_server, iv_server = server.echo(cipher, iv)

        aes = AES.new(key, AES.MODE_CBC, iv_server)
        plain_server = aes.decrypt(cipher_server)
        self.assertEqual(plain, plain_server)


    def test_33(self):
        private_1, public_1 = ck.gen_DH_keys()
        private_2, public_2 = ck.gen_DH_keys()

        shared_1 = ck.gen_DH_secret(private_1, public_2)
        shared_2 = ck.gen_DH_secret(private_2, public_1)
        self.assertEqual(shared_1, shared_2)

    def test_34(self):
        server = BobServer()
        mitm = EveServer(server)

        """Alice generates DH parameters, sends to server (Eve), generates
        shared secret according to Diffie-Hellman"""
        p, g = ck.DH_P, ck.DH_G
        private, public = ck.gen_DH_keys()
        public_Bob = mitm.key_exchange(p, g, public)
        secret = ck.gen_DH_secret(private, public_Bob)

        """Use secret to encrypt a random message, send to server, and get
        ciphertext. Verify that it encrypts the same plaintext."""
        iv = cu.random_bytes()
        key = cbc_keygen(secret)
        aes = AES.new(key, AES.MODE_CBC, iv)
        plain = cu.random_bytes(count=256)
        cipher = aes.encrypt(plain)
        cipher_server, iv_server = mitm.echo(cipher, iv)

        aes = AES.new(key, AES.MODE_CBC, iv_server)
        plain_server = aes.decrypt(cipher_server)
        self.assertEqual(plain, plain_server)

        """Now, check that Eve was able to decrypt Alice and Bob's messages"""
        self.assertEqual(plain, mitm.last_client_msg)
        self.assertEqual(plain, mitm.last_server_msg)

