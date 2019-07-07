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






