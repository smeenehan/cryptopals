import crypto_utils as cu
from Crypto.Cipher import AES
from random import choice, randint
from unittest import TestCase

RANDOM_PLAINS = [
b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
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

    def test_17(self):
        cipher = encrypt_random()
        plain = cu.decrypt_CBC_padding_oracle(cipher, pad_check)
        plain = cu.unpad_PKCS7(plain)
        self.assertTrue(plain in RANDOM_PLAINS)

    def test_18(self):
        cipher = cu.base64_to_bytes('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
        expect = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
        key = b'YELLOW SUBMARINE'
        plain = cu.AES_CTR(cipher, key)
        self.assertEqual(plain, expect)

    def test_19_20(self):
        cipher_list = []
        plain_list = []
        key = cu.random_bytes()
        with open('data/Set_3_19.txt', 'r') as f:
            for line in f:
                plain = cu.base64_to_bytes(line)
                plain_list.append(plain)
                cipher_list.append(cu.AES_CTR(plain, key))
        with open('data/Set_3_20.txt', 'r') as f:
            for line in f:
                plain = cu.base64_to_bytes(line)
                plain_list.append(plain)
                cipher_list.append(cu.AES_CTR(plain, key))

        min_len = len(min(cipher_list, key=len))
        cipher_trunc = [x[:min_len] for x in cipher_list]
        cipher_cat = b''. join(cipher_trunc)
        keystream = cu.get_repeating_XOR_key(cipher_cat, min_len)
        plain_cat = cu.XOR_bytes(keystream, cipher_cat)
        plain_trunc = [plain_cat[x:x+min_len] for x in range(0, len(plain_cat), min_len)]
        total, correct = 0, 0
        for real, guess in zip(plain_list, plain_trunc):
            total += 1
            correct +=  real[:min_len].decode('utf-8').lower()==guess.decode('utf-8').lower()
        self.assertTrue(correct/total>0.95)

    def test_21(self):
        mt_output = []
        with open('data/MT19937_out.txt', 'r') as f:
            for line in f:
                mt_output.append(int(line))
        mt_gen = cu.MT19937_gen(seed=0)
        for truth, test in zip(mt_output, mt_gen):
            self.assertEqual(truth, test)
