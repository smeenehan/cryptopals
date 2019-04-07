from hashlib import sha1, sha256
import hmac
from random import choice
from secrets import randbelow
from unittest import TestCase

from Crypto.Cipher import AES

import crypto.hash as ch
import crypto.key_exchange as ck
import crypto.utils as cu

class Set5DH(TestCase):

    def setUp(self):
        self.client = Alice()
        self.server = Bob()
        self.mitm = Eve(self.server)

    def test_33(self):
        private_1, public_1 = ck.gen_DH_keys()
        private_2, public_2 = ck.gen_DH_keys()

        shared_1 = ck.gen_DH_secret(private_1, public_2)
        shared_2 = ck.gen_DH_secret(private_2, public_1)
        self.assertEqual(shared_1, shared_2)

    def test_DH_echo(self):
        self.assertTrue(self.client.connect_to_server(self.server))
        good_cnxn, _ = self.client.check_connection()
        self.assertTrue(good_cnxn)

    def test_34(self):
        self.client.connect_to_server(self.mitm)
        good_cnxn, plain = self.client.check_connection()
        self.assertTrue(good_cnxn)

        """Check that Eve was able to decrypt Alice and Bob's messages"""
        self.assertEqual(plain, self.mitm.last_client_msg)
        self.assertEqual(plain, self.mitm.last_server_msg)

    def test_35(self):
        self.mitm.mod_g = True
        self.client.connect_to_server(self.mitm)
        good_cnxn, plain = self.client.check_connection()
        self.assertTrue(good_cnxn)

        """Check that Eve was able to decrypt Alice and Bob's messages"""
        self.assertEqual(plain, self.mitm.last_client_msg)
        self.assertEqual(plain, self.mitm.last_server_msg)

class Set5SRP(TestCase):

    def setUp(self):
        g, N, k = 2, ck.DH_P, 3
        email = 'oldirty@wu-tang-financial.com'
        password = 'beetle-bailey-rhymes'
        self.client = SRPClient(email, password, g=g, N=N, k=k)
        self.server = SRPServer(g, N, k)
        self.server.register_user(email, password)
        self.client.server = self.server

    def test_36(self):
        self.client.login()
        self.assertTrue(self.client.validate())

    def test_37(self):
        """Since SRP, server-side, multiplies by the client's public key prior
        to modexp and hashing, passing any multiple of N (including 0!) will
        result in key == SHA256(0). Note that we don't need to know g, N, k,
        the password. NOTHING. Just pass (email, 0) and SHA256(0) is your key!!!"""
        self.client.login(DH_keys=(0, 0))
        m = sha256()
        m.update(cu.int_to_bytes(0))
        self.client.session_key = m.digest()
        self.assertTrue(self.client.validate())

    def test_SRP_simple(self):
        self.server.simple = True
        self.client.login()
        self.assertTrue(self.client.validate())

class Alice(object):
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

class Bob(object):
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

class Eve(object):
    """Mock up a server where Eve acts as a MITM between Alice and Bob."""

    def __init__(self, server):
        self.server = server
        self.key = cbc_keygen(bytes([]))
        self.last_client_msg = bytes([])
        self.last_server_mas = bytes([])
        self.mod_g = False

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

class SRPClient(object):
    """Mock up a client for Secure Remote Password authentication."""

    def __init__(self, email, password, g=ck.DH_G, N=ck.DH_P, k=3):
        self.email = email
        self.password = password
        self.g, self.N, self.k = g, N, k
        self.server = None
        self.session_key = None
        self.salt = None

    def login(self, DH_keys=None):
        if DH_keys is None:
            private, public = ck.gen_DH_keys(p=self.N, g=self.g)
        else:
            private, public = DH_keys

        response = self.server.login(self.email, public)
        if self.server.simple:
            self.salt, server_public, scramble = response
        else:
            self.salt, server_public = response
            scramble = srp_scrambler(public, server_public)

        m = sha256()
        m.update(self.salt+bytes(self.password, 'utf-8'))
        xH = m.digest()
        x = int.from_bytes(xH, byteorder='big')
        if self.server.simple:
            S = ck.modexp(server_public, private+scramble*x, self.N)
        else:
            S = ck.modexp(self.g, x, self.N)
            S = ck.modexp(server_public-self.k*S, private+scramble*x, self.N)
        m = sha256()
        m.update(cu.int_to_bytes(S))
        self.session_key = m.digest()

    def validate(self):
        """Use existing session key and salt to send a HMAC to the server
        for validation."""
        validation = hmac.new(self.session_key, self.salt, sha256).digest()
        return self.server.validate(self.email, validation)

class SRPServer(object):
    """Mock up a Secure Remote Password-like authentication. If simple is
    specified, we'll use a simplified version of SRP which doesn't use the
    password verifier in the public key returned by the server"""

    def __init__(self, g, N, k):
        self.login_info = dict()
        self.session_keys = dict()
        self.g, self.N, self.k = g, N, k
        self.simple = False

    def register_user(self, email, password):
        salt = cu.random_bytes(8)
        m = sha256()
        m.update(salt+bytes(password, 'utf-8'))
        xH = m.digest()
        x = int.from_bytes(xH, byteorder='big')
        verifier = ck.modexp(self.g, x, self.N)
        self.login_info[email] = (salt, verifier)

    def login(self, email, client_public):
        if self.simple:
            return self._srp_key_simple(email, client_public)
        else:
            return self._srp_key_standard(email, client_public)

    def _srp_key_simple(self, email, client_public):
        salt, verifier = self.login_info[email]
        private, public = ck.gen_DH_keys(p=self.N, g=self.g)

        # compute and store session key
        scramble = randbelow(2**128)
        S = ck.modexp(verifier, scramble, self.N)
        S = ck.modexp(client_public*S, private, self.N)
        m = sha256()
        m.update(cu.int_to_bytes(S))
        self.session_keys[email] = m.digest()

        return salt, public, scramble

    def _srp_key_standard(self, email, client_public):
        salt, verifier = self.login_info[email]
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

    def validate(self, email, validation):
        try:
            salt, _ = self.login_info[email]
            key = self.session_keys[email]
            expected = hmac.new(key, salt, sha256).digest()
            return hmac.compare_digest(validation, expected)
        except KeyError:
            return False

def srp_scrambler(client_public, server_public):
    """compute the scrambling integer used in the SRP protocal, using two
    ephemeral public keys"""
    m = sha256()
    m.update(cu.int_to_bytes(client_public)+cu.int_to_bytes(server_public))
    return int.from_bytes(m.digest(), byteorder='big')








