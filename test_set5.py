from hashlib import sha1, sha256
import hmac
from random import choice
from unittest import TestCase

from Crypto.Cipher import AES

import crypto.hash as ch
import crypto.key_exchange as ck
import crypto.utils as cu

class AliceClient(object):
    """Mock up client that will do encrypted communication with a server
    using Diffie-Hellman key-exchange"""

    def __init__(self):
        self.p, self.g = ck.DH_P, ck.DH_G
        self.private, self.public = 0, 0
        self.key = bytes([])
        self.server = None

    def connect_to_server(self, server):
        """Perform key-exchange with a server to generate a shared-secret"""
        self.private, self.public = ck.gen_DH_keys(p=self.p, g=self.g)
        public_server = server.key_exchange(self.p, self.g, self.public)
        secret = ck.gen_DH_secret(self.private, public_server, p=self.p)
        self.key = cbc_keygen(secret)
        self.server = server
        return True

    def check_connection(self):
        """Encrypt a random message, send to server, and check that the
        response is a valid encrypted echo of that message."""
        iv = cu.random_bytes()
        aes = AES.new(self.key, AES.MODE_CBC, iv)
        plain = cu.random_bytes(count=256)
        cipher = aes.encrypt(plain)
        cipher_server, iv_server = self.server.echo(cipher, iv)
        aes = AES.new(self.key, AES.MODE_CBC, iv_server)
        plain_server = aes.decrypt(cipher_server)
        return plain==plain_server, plain

class BobServer(object):
    """Mock up a server where Bob can do Diffie-Hellman key-exchange, and
    use this to echo back encrypted messages using the shared secret."""

    def __init__(self):
        self.p, self.g = ck.DH_P, ck.DH_G
        self.private, self.public = 0, 0
        self.secret = bytes([])

    def key_exchange(self, p, g, public):
        self.p, self.g = p, g
        self.private, self.public = ck.gen_DH_keys(p=self.p, g=self.g)
        self.secret = ck.gen_DH_secret(self.private, public, p=self.p)
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
    (the latter using the BobServer object)."""

    def __init__(self, server, mod_g=False):
        self.server = server
        self.key = cbc_keygen(bytes([]))
        self.last_client_msg = bytes([])
        self.last_server_mas = bytes([])
        self.mod_g = mod_g

    def key_exchange(self, p, g, public):
        if self.mod_g is False:
            """Parameter-injection. Make both parties think the public-key
            is p, yielding a secret of 0 (empty bytes)"""
            self.server.key_exchange(p, g, p)
            return p

        """Malicious g-value, but same idea. Control the estimated public-key
        so that the secret is known a priori"""
        new_g = choice([1, p, p-1])
        if new_g == p:
            fake_public, secret = 0, 0
        else:
            fake_public, secret = 1, 1
        self.key = cbc_keygen(cu.int_to_bytes(secret))
        return self.server.key_exchange(p, new_g, fake_public)

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

def srp_scrambler(client_public, server_public):
    """compute the scrambling integer used in the SRP protocal, using two
    ephemeral public keys"""
    m = sha256()
    m.update(cu.int_to_bytes(client_public)+cu.int_to_bytes(server_public))
    return int.from_bytes(m.digest(), byteorder='big')

class SRPServer(object):
    """Mock up a Secure Remote Password-like authentication"""
    def __init__(self, g, N, k):
        self.user_info = dict()
        self.session_keys = dict()
        self.g, self.N, self.k = g, N, k

    def register_user(self, email, password):
        salt = cu.random_bytes(8)
        m = sha256()
        m.update(salt+bytes(password, 'utf-8'))
        xH = m.digest()
        x = int.from_bytes(xH, byteorder='big')
        verifier = ck.modexp(self.g, x, self.N)
        self.user_info[email] = (salt, verifier)

    def init_connect(self, email, client_public):
        salt, verifier = self.user_info[email]
        private, public = ck.gen_DH_keys(p=self.N, g=self.g)
        public = (public+self.k*verifier)%self.N

        # compute and store session key
        scramble = srp_scrambler(client_public, public)
        S = ck.modexp(verifier, scramble, self.N)
        S = ck.modexp(client_public*S, private, self.N)
        m = sha256()
        m.update(cu.int_to_bytes(S))
        self.session_keys[email] = m.digest()

        return salt, public

    def validate_session(self, email, validation):
        try:
            salt, _ = self.user_info[email]
            key = self.session_keys[email]
            expected = hmac.new(key, salt, sha256).digest()
            return hmac.compare_digest(validation, expected)
        except KeyError:
            return False

class Set5(TestCase):

    def test_DH_echo(self):
        client = AliceClient()
        server = BobServer()
        client.connect_to_server(server)
        good_cnxn, _ = client.check_connection()
        self.assertTrue(good_cnxn)

    def test_33(self):
        private_1, public_1 = ck.gen_DH_keys()
        private_2, public_2 = ck.gen_DH_keys()

        shared_1 = ck.gen_DH_secret(private_1, public_2)
        shared_2 = ck.gen_DH_secret(private_2, public_1)
        self.assertEqual(shared_1, shared_2)

    def test_34(self):
        client = AliceClient()
        server = BobServer()
        mitm = EveServer(server)
        client.connect_to_server(mitm)
        good_cnxn, plain = client.check_connection()
        self.assertTrue(good_cnxn)

        """Check that Eve was able to decrypt Alice and Bob's messages"""
        self.assertEqual(plain, mitm.last_client_msg)
        self.assertEqual(plain, mitm.last_server_msg)

    def test_35(self):
        client = AliceClient()
        server = BobServer()
        mitm = EveServer(server, mod_g=True)
        client.connect_to_server(mitm)
        good_cnxn, plain = client.check_connection()
        self.assertTrue(good_cnxn)

        """Check that Eve was able to decrypt Alice and Bob's messages"""
        self.assertEqual(plain, mitm.last_client_msg)
        self.assertEqual(plain, mitm.last_server_msg)

    def test_36(self):
        email = 'oldirty@wu-tang-financial.com'
        password = 'beetle-bailey-rhymes'
        g, N, k = 2, ck.DH_P, 3
        server = SRPServer(g, N, k)
        server.register_user(email, password)

        # initiate SRP connection
        private, public = ck.gen_DH_keys(p=N, g=g)
        salt, server_public = server.init_connect(email, public)

        # compute session key client-side
        scramble = srp_scrambler(public, server_public)
        m = sha256()
        m.update(salt+bytes(password, 'utf-8'))
        xH = m.digest()
        x = int.from_bytes(xH, byteorder='big')
        S = ck.modexp(g, x, N)
        S = ck.modexp(server_public-k*S, private+scramble*x, N)
        m = sha256()
        m.update(cu.int_to_bytes(S))
        session_key = m.digest()

        validation = hmac.new(session_key, salt, sha256).digest()
        self.assertTrue(server.validate_session(email, validation))

    def test_37(self):
        email = 'oldirty@wu-tang-financial.com'
        password = 'beetle-bailey-rhymes'
        g, N, k = 2, ck.DH_P, 3
        server = SRPServer(g, N, k)
        server.register_user(email, password)

        """Because SRP on the client side generates the session key multiplies
        by the client's public key prior to modexp and hashing, passing any
        multiple of N (including 0!) will result in the session key just being
        the SHA256 hash of 0. Note that we don't even need to know g, N, k, the
        password. NOTHING. Just pass (email, 0) and SHA256(0) is your key!!!"""
        salt, _ = server.init_connect(email, 0)
        m = sha256()
        m.update(cu.int_to_bytes(0))
        session_key = m.digest()

        validation = hmac.new(session_key, salt, sha256).digest()
        self.assertTrue(server.validate_session(email, validation))








