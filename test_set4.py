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
