import crypto_utils as cu
from Crypto.Cipher import AES
from random import choice, randint
from unittest import TestCase

RANDOM_PLAINS = [
# b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
# b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
# b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
# b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
# b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
# b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
# b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
# b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
# b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
# b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
b'YELLOW SUBMARINE'
]

UNKNOWN_KEY = cu.random_bytes()
UNKNOWN_IV = cu.random_bytes()

def encrypt_random():
    plain = choice(RANDOM_PLAINS)
    return UNKNOWN_IV+cu.encrypt_AES_CBC(plain, UNKNOWN_KEY, iv=UNKNOWN_IV)

def pad_check(cipher):
    iv = cipher[:AES.block_size]
    cipher = cipher[AES.block_size:]
    plain = cu.decrypt_AES_CBC(cipher, UNKNOWN_KEY, iv=iv)
    try:
        _ = cu.unpad_PKCS7(plain)
        return True
    except ValueError:
        return False

class Set3(TestCase):

    def test_pad_oracle(self):
        self.assertTrue(pad_check(encrypt_random()))

    # def test_17(self):
    #     cipher = encrypt_random()
    #     plain = cu.decrypt_CBC_padding_oracle(cipher, pad_check)
    #     print(plain)
    #     print(len(plain))
    #     self.assertTrue(plain in RANDOM_PLAINS)
