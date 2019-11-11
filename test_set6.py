from decimal import Decimal, getcontext
from hashlib import sha1
from math import ceil, log
from secrets import randbelow
from unittest import TestCase

import crypto.key_exchange as ck
import crypto.utils as cu

# ASN.1 DER for SHA1, used in signature padding. Just hardcoded for ease.
SHA1_ASN = bytes([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14])

def get_sha1_int(message):
    """Return SHA-1 hash of bytes-like as an integer"""
    m = sha1()
    m.update(message)
    return int.from_bytes(m.digest(), 'big')

def get_message_recovery_oracle():
    """Return RSA public key, and an oracle function, which will decrypt
    and return any message encrypted with the public key exactly once
    """
    public, private = ck.gen_RSA_keys()
    previous = []
    def oracle(cipher):
        if cipher in previous:
            raise ValueError('Ciphertext previously submitted')
        previous.append(cipher)
        return ck.cipher_RSA(cipher, private)
    return public, oracle

def sign_RSA(message_hash, private, N=1024):
    """Sign a message hash with a private key, with N-bit RSA, PKCS#1.5 padding"""
    prepad = bytes([0x01])
    postpad = bytes([0x00])+SHA1_ASN
    pad_length = N//8-len(prepad)-len(postpad)-len(message_hash)
    pad = prepad+bytes([0xff]*pad_length)+postpad

    plain = pad+message_hash
    signature = ck.cipher_RSA(plain, private)
    return signature, plain

def verify_RSA(message_hash, signature, public):
    """Return true if a given RSA signature and public key matches a message hash.
    Note that this is deliberately implemented poorly so we can attack it
    """
    padded_hash = ck.cipher_RSA(signature, public)

    if padded_hash[:2] != bytes([0x01, 0xff]):
        raise ValueError('Incorrect padding')

    stripped = None
    for idx in range(2, len(padded_hash)):
        """This is the problem! We check that we have a string of 0xff
        followed by the right ASN.1 and hash, but don't check that the
        number of 0xffs is such that the hash is right-justified."""
        if padded_hash[idx] != 0xff:
            stripped = padded_hash[idx:]
            break

    # hard-coded to use SHA1
    if stripped[:16] != bytes([0])+SHA1_ASN:
        raise ValueError('Incorrect padding')

    sig_hash = stripped[16:36]
    return sig_hash == message_hash

def get_parity_oracle():
    """Return RSA public key, and oracle function, which will decrypt
    messages encrypted with the public key and return True or False
    depending on whether the plaintext (as integer) is even or odd
    """
    public, private = ck.gen_RSA_keys()
    previous = []
    def oracle(cipher):
        plain = ck.cipher_RSA(cipher, private)
        return not (plain % 2)
    return public, oracle

def PKCS1v1p5(plain, N):
    num_bytes = ceil(N/8)
    plain_bytes = cu.int_to_bytes(plain)
    num_pad = num_bytes-3-len(plain_bytes)
    padding = cu.random_bytes(num_pad)
    padded = bytes([0, 2])+padding+bytes([0])+plain_bytes
    return int.from_bytes(padded,'big')

def get_PKCS_oracle(N):
    """Return RSA public key, and oracle function, which will decrypt
    messages encrypted with the public key and return True or False
    depending on whether or not the plaintest has a valid PCKS#1v1.5
    padding"""
    strong = N>512
    public, private = ck.gen_RSA_keys(N=N, strong=strong)
    B = 2**(N-16)
    def oracle(cipher):
        plain = ck.cipher_RSA(cipher, private)
        return (plain>=2*B) and (plain<3*B)
    return public, oracle


class Set6(TestCase):

    def test_message_recovery_oracle(self):
        public, oracle = get_message_recovery_oracle()

        plain = randbelow(2**64)
        cipher = ck.cipher_RSA(plain, public)
        decipher = oracle(cipher)
        self.assertEqual(plain, decipher)
        self.assertRaises(ValueError, oracle, cipher)

    def test_sign_RSA(self):
        message = b'hi mom'
        m = sha1()
        m.update(message)
        message_hash = m.digest()
        public, private = ck.gen_RSA_keys()
        signature, plain = sign_RSA(message_hash, private)
        self.assertTrue(verify_RSA(message_hash, signature, public))

    def test_DSA(self):
        public, private = ck.gen_DSA_keys()
        message = cu.random_bytes(count=128)
        message_hash = get_sha1_int(message)
        signature = ck.sign_DSA(message_hash, private)
        self.assertTrue(ck.verify_DSA(message_hash, signature, public))

    def test_PKCS(self):
        N = 1024
        public, oracle = get_PKCS_oracle(N=N)
        plain = randbelow(2**64)
        padded = PKCS1v1p5(plain, N)
        self.assertEqual(len(cu.int_to_bytes(padded)), ceil(N/8)-1)

        cipher = ck.cipher_RSA(padded, public)
        self.assertTrue(oracle(cipher))

    # Unpadded RSA message recovery oracle attack
    def test_41(self):
        public, oracle = get_message_recovery_oracle()

        plain = randbelow(2**64)
        cipher = ck.cipher_RSA(plain, public)
        _ = oracle(cipher)

        s = 2
        e, n = public
        new_cipher = ck.cipher_RSA(s, public)*cipher % n
        new_plain = oracle(new_cipher)
        s_inv = ck.modinv(s, n)
        recovered = s_inv*new_plain % n
        self.assertEqual(plain, recovered)

    # Forging RSA signature for e=3 (Bleichenbacher's attack)
    def test_42(self):
        # we only know the public key, so we have to forge the signature
        public, _ = ck.gen_RSA_keys(N=3072)

        message = b'hi mom'
        m = sha1()
        m.update(message)
        message_hash = m.digest()
        block = bytes([0])+SHA1_ASN+message_hash

        """Bleichenbacher's 'pencil and paper' attack strategy doesn't
         work for smaller moduli (e.g., N=1024), and via brute-forcing I
        couldn't find a zero-padded forged signature that worked, so I'm
        saying screw it and doing this for 3072 bit RSA"""
        D = int.from_bytes(block, 'big')
        M = 2**288-D
        F = 2**1019-2**34*M//3
        forged = cu.int_to_bytes(F)

        self.assertTrue(verify_RSA(message_hash, forged, public))

    # DSA private key recovery using small nonce
    def test_43(self):
        public = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
        message = b'For those that envy a MC it can be hazardous to your health\n' \
            +b'So be friendly, a matter of life and death, just like a etch-a-sketch\n'
        message_hash = 0xd2d0714f014a9784047eaeccf956520045c45265
        signature = (548099063082341131477253921760299949438196259240,
                     857042759984254168557880549501802188789837994940)
        private_hash = cu.hex_to_bytes('0954edd5e0afe5542a4adf012611a91912a3ec16')

        private = None
        for k in range(2**16):
            private_guess = ck.recover_DSA_private(message_hash, signature, k)
            public_guess = pow(ck.DSA_G, private_guess, ck.DSA_P)
            if public_guess == public:
                private = private_guess
                break

        m = sha1()
        m.update(hex(private)[2:].encode())
        private_hash = m.digest()
        self.assertEqual(cu.bytes_to_hex(private_hash), '0954edd5e0afe5542a4adf012611a91912a3ec16')

    # DSA key recovery using repeated nonce
    def test_44(self):
        public = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
        with open('data/Set_6_44.txt') as f:
            lines = [x.strip('\n').split(': ')[1] for x in f.readlines()]
        messages = lines[::4]
        ss = [int(x) for x in lines[1::4]]
        rs = [int(x) for x in lines[2::4]]
        ms = [int(x, 16) for x in lines[3::4]]

        """Find signed messages with the same r. If the algorithm parameters
        (p, q, g) are the same, this can only mean they share the same k"""
        idx1, idx2 = 0, 0
        for idx, r in enumerate(rs):
            rest = rs[idx+1:]
            jdx = rest.index(r) if r in rest else Non
            if jdx is not None:
                idx1, idx2 = idx, jdx+idx+1
                break
        m1, m2 = ms[idx1], ms[idx2]
        r1, r2 = rs[idx1], rs[idx2]
        s1, s2 = ss[idx1], ss[idx2]

        s_diff = s1-s2 % ck.DSA_Q
        inv_diff = ck.modinv(s_diff, ck.DSA_Q)
        m_diff = m1-m2 % ck.DSA_Q
        k = inv_diff*(m_diff) % ck.DSA_Q

        private = ck.recover_DSA_private(m1, (r1, s1), k)
        m = sha1()
        m.update(hex(private)[2:].encode())
        private_hash = m.digest()
        self.assertEqual(cu.bytes_to_hex(private_hash), 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
        self.assertEqual(pow(ck.DSA_G, private, ck.DSA_P), public)

    # Breaking DSA with malicious selection of parameters
    def test_45(self):
        m_hash_1 = get_sha1_int(b'Hello, world')
        m_hash_2 = get_sha1_int(b'Goodbye, world')

        public, _ = ck.gen_DSA_keys()

        """Case g = 0 (mod p). Since the verifier v is proprotional to
        g**u (mod p), it will always be 0, so any signature where r = 0
        looks valid. This only works if we don't check r and s beforehand,
        so it's kind of lame."""

        """Case g = 1 (mod p). More interesting since we generate a signature
        (r, s) that will validate but it not obviously invalid (e.g., r != 0)"""
        z = randbelow(2**16)
        r = pow(public, z, ck.DSA_P) % ck.DSA_Q
        z_inv = ck.modinv(z, ck.DSA_Q)
        s = z_inv*r % ck.DSA_Q

        self.assertTrue(ck.verify_DSA(m_hash_1, (r, s), public, g=ck.DSA_P+1))
        self.assertTrue(ck.verify_DSA(m_hash_2, (r, s), public, g=ck.DSA_P+1))

    # RSA decryption using a parity oracle
    def test_46(self):
        plain = cu.base64_to_bytes('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
        plain_int = int.from_bytes(plain, 'big')

        public, is_even = get_parity_oracle()
        e, n = public
        cipher = ck.cipher_RSA(plain_int, public)

        # constant which will allow us to double the plaintext
        double_plain = pow(2, e, n)
        max_iter = ceil(log(n, 2))

        """casting the bounds as Decimal type, and setting the precision
        to have as many bits as the modulus, is *super* important. If we
        don't do this rounding errors will screw us, and trying to do this
        with integer division without messing up the last byte is annoying"""
        lower_bound, upper_bound = Decimal(0), Decimal(n)
        getcontext().prec = max_iter
        for _ in range(max_iter):
            cipher = double_plain*cipher % n
            if is_even(cipher):
                upper_bound = (lower_bound+upper_bound)/2
            else:
                lower_bound = (lower_bound+upper_bound)/2
            if int(upper_bound) == int(lower_bound):
                break

        decrypted = cu.int_to_bytes(int(upper_bound))
        self.assertEqual(plain, decrypted)
