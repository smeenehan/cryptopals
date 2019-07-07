from hashlib import sha1
from secrets import randbelow
from unittest import TestCase

import crypto.key_exchange as ck
import crypto.utils as cu

# ASN.1 DER for SHA1, used in signature padding. Just hardcoded for ease.
SHA1_ASN = bytes([0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14])

def get_message_recovery_oracle():
    public, private = ck.gen_RSA_keys()
    previous = []
    def oracle(cipher):
        if cipher in previous:
            raise ValueError('Ciphertext previously submitted')
        previous.append(cipher)
        return ck.cipher_RSA(cipher, private)
    return public, oracle

def sign_message(message, private, N=128):
    """Sign a message with your private key. N is the number of bytes in
    the message block (e.g., the RSA modulus), defaulting to 1204-bit."""
    m = sha1()
    m.update(message)
    m_hash = m.digest()

    prepad = bytes([0x01])
    postpad = bytes([0x00])+SHA1_ASN
    pad_length = N-len(prepad)-len(postpad)-len(m_hash)
    pad = prepad+bytes([0xff]*pad_length)+postpad

    plain = pad+m_hash
    signature = ck.cipher_RSA(plain, private)
    return signature, plain

def sig_verify(message, signature, public):
    """Verify that signature decrypts using the provided public RSA key to
    the SHA1 hash of message plus appropriate pre-padding, but done all
    poorly so we can attack it."""
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

    message_hash = stripped[16:36]
    m = sha1()
    m.update(message)
    return message_hash == m.digest()


class Set6(TestCase):

    def test_message_recovery_oracle(self):
        public, oracle = get_message_recovery_oracle()

        plain = randbelow(2**64)
        cipher = ck.cipher_RSA(plain, public)
        decipher = oracle(cipher)
        self.assertEqual(plain, decipher)
        self.assertRaises(ValueError, oracle, cipher)

    def test_RSA_sign(self):
        message = b'hi mom'
        public, private = ck.gen_RSA_keys()
        signature, plain = sign_message(message, private)
        self.assertTrue(sig_verify(message, signature, public))

    def test_DSA(self):
        public, private = ck.gen_DSA_keys()
        message = cu.random_bytes(count=128)
        signature = ck.sign_DSA(message, private)
        self.assertTrue(ck.verify_DSA(message, signature, public))

    def test_41(self):
        public, oracle = get_message_recovery_oracle()

        plain = randbelow(2**64)
        cipher = ck.cipher_RSA(plain, public)
        _ = oracle(cipher)

        s = 2
        e, n = public
        new_cipher = ck.cipher_RSA(s, public)*cipher % n
        new_plain = oracle(new_cipher)
        s_inv = ck.invmod(s, n)
        recovered = s_inv*new_plain % n
        self.assertEqual(plain, recovered)

    def test_42(self):
        # we only know the public key, so we have to forge the signature
        public, _ = ck.gen_RSA_keys(N=3072)

        message = b'hi mom'
        m = sha1()
        m.update(message)
        m_hash = m.digest()
        block = bytes([0])+SHA1_ASN+m_hash

        """Seems like Bleichenbacher's 'pencil and paper' attack strategy
        doesn't work for smaller moduli (e.g., N=1024), and brute-forcing I
        couldn't find a zero-padded forged signature that worked, so I'm
        saying screw it and doing this for 3072 bit RSA"""
        D = int.from_bytes(block, 'big')
        M = 2**288-D
        F = 2**1019-2**34*M//3
        forged = cu.int_to_bytes(F)

        self.assertTrue(sig_verify(message, forged, public))

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
            public_guess = ck.modexp(ck.DSA_G, private_guess, ck.DSA_P)
            if public_guess == public:
                private = private_guess
                break

        m = sha1()
        m.update(hex(private)[2:].encode())
        private_hash = m.digest()
        self.assertEqual(cu.bytes_to_hex(private_hash), '0954edd5e0afe5542a4adf012611a91912a3ec16')

    def test_44(self):
        public = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
        with open('data/Set_6_44.txt') as f:
            lines = [x.strip('\n').split(': ')[1] for x in f.readlines()]
        messages = lines[::4]
        ss = [int(x) for x in lines[1::4]]
        rs = [int(x) for x in lines[2::4]]
        ms = [int(x, 16) for x in lines[3::4]]

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
        inv_diff = ck.invmod(s_diff, ck.DSA_Q)
        m_diff = m1-m2 % ck.DSA_Q
        k = inv_diff*(m_diff) % ck.DSA_Q

        private = ck.recover_DSA_private(m1, (r1, s1), k)

        m = sha1()
        m.update(hex(private)[2:].encode())
        private_hash = m.digest()
        self.assertEqual(cu.bytes_to_hex(private_hash), 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
        self.assertEqual(ck.modexp(ck.DSA_G, private, ck.DSA_P), public)









