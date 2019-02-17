import crypto_utils as cu
from Crypto.Cipher import AES
from datetime import datetime
from random import choice, randint
from string import printable
from test_set2 import encrypt16, decrypt16
from unittest import TestCase

def encrypt27():
    key = cu.random_bytes()
    plain = b"For you to even touch my skill, you gotta put the one killer bee and he ain't gonna kill"
    return cu.encrypt_AES_CBC(plain, key, iv=key), key

def decrypt27(cipher, key):
    plain = cu.decrypt_AES_CBC(cipher, key, iv=key)
    if not all([x>31 and x<128 for x in plain]):
        raise ValueError(plain)

class Set4(TestCase):

    def test_ctr_edit(self):
        plain = cu.random_bytes(count=10*AES.block_size)
        key = cu.random_bytes()
        nonce = cu.random_bytes(count=AES.block_size//2)
        ctr = cu.AES_CTR(key, nonce=nonce)
        cipher = ctr.process(plain)

        new_plain_block = cu.random_bytes(count=2*AES.block_size+5)
        new_plain = bytearray(plain)
        offset_block = 4
        offset = offset_block*AES.block_size
        new_plain[offset:offset+len(new_plain_block)] = new_plain_block
        new_cipher = ctr.edit(cipher, offset_block, new_plain_block)

        ctr.reset()
        test = ctr.process(new_cipher)
        self.assertEqual(new_plain, test)

    def test_rotate(self):
        orig = 0b10010110011010011001011001101001
        rotl = 0b10110011010011001011001101001100
        rotr = 0b00110010110011010011001011001101
        self.assertEqual(cu.rot_left(orig, 3, 32), rotl)
        self.assertEqual(cu.rot_right(orig, 3, 32), rotr)

    def test_bit_not(self):
        orig = 0b10110011010011001011001101001000
        not_orig = 0b01001100101100110100110010110111
        self.assertTrue(cu.bit_not(orig, 32), not_orig)

    def test_sha_1(self):
        message_1 = b'The quick brown fox jumps over the lazy dog'
        message_2 = b'The quick brown fox jumps over the lazy cog'
        message_3 = b''
        digest_1 = cu.hex_to_bytes('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')
        digest_2 = cu.hex_to_bytes('de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3')
        digest_3 = cu.hex_to_bytes('da39a3ee5e6b4b0d3255bfef95601890afd80709')
        self.assertEqual(cu.SHA_1(message_1), digest_1)
        self.assertEqual(cu.SHA_1(message_2), digest_2)
        self.assertEqual(cu.SHA_1(message_3), digest_3)

    # Break "random access read/write" CTR
    def test_25(self):
        key = cu.random_bytes()
        nonce = cu.random_bytes(count=AES.block_size//2)
        plain = cu.read_base64('data/Set_1_7.txt')
        ctr = cu.AES_CTR(key, nonce=nonce)
        cipher = ctr.process(plain)

        cipher_len = len(cipher)
        new_plain = bytes([14]*cipher_len)
        new_cipher = ctr.edit(cipher, 0, new_plain)
        keystream = cu.XOR_bytes(new_plain, new_cipher)
        recovered_plain = cu.XOR_bytes(keystream, cipher)

        self.assertEqual(recovered_plain, plain)

    # CTR bitflipping attack
    def test_26(self):
        """As in the CBC bitflip attack, we'll assume we know the exact prefix
        size (2 blocks) and how the forbidden characters are handled."""
        plain = b';admin=True'
        cipher = bytearray(encrypt16(plain, CTR=True))
        cipher[32] = cu.XOR_bytes(b'?', cu.XOR_bytes(bytes([cipher[32]]), b';'))[0]
        cipher[38] = cu.XOR_bytes(b'?', cu.XOR_bytes(bytes([cipher[38]]), b'='))[0]
        self.assertTrue(decrypt16(cipher, CTR=True))

    # Recover CBC key when IV=key
    def test_27(self):
        for _ in range(10):
            cipher, key = encrypt27()
            c_0 = cipher[:AES.block_size]
            c_end = cipher[3*AES.block_size:]
            cipher = c_0+bytes([0]*AES.block_size)+c_0+c_end
            try:
                decrypt27(cipher, key)
            except ValueError as e:
                plain = e.args[0]
                break
        p_0 = plain[:AES.block_size]
        p_2 = plain[2*AES.block_size:3*AES.block_size]
        d_0 = cu.XOR_bytes(p_2, bytes([0]*AES.block_size))
        recovered_key = cu.XOR_bytes(d_0, p_0)
        self.assertTrue(recovered_key, key)
