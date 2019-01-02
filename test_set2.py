import crypto_utils as cu
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from math import inf
from random import choice, randint
from unittest import TestCase

UNKNOWN_KEY = cu.random_bytes()
UNKNOWN_PLAIN = cu.base64_to_bytes(
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYm'\
   +'xvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91'\
   +'IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

def encryption_oracle(plain):
    key = cu.random_bytes()
    encrypt_ECB = choice([True, False])
    before_bytes = cu.random_bytes(count=randint(5, 10))
    after_bytes = cu.random_bytes(count=randint(5, 10))
    plain = before_bytes+plain+after_bytes
    if encrypt_ECB:
        aes = AES.new(key, AES.MODE_ECB)
        plain = cu.pad_PKCS7(plain)
        return aes.encrypt(plain)
    else:
        iv = cu.random_bytes()
        return cu.encrypt_AES_CBC(plain, key, iv=iv)

def black_box(plain):
    aes = AES.new(UNKNOWN_KEY, AES.MODE_ECB)
    plain = plain+UNKNOWN_PLAIN
    plain = cu.pad_PKCS7(plain)
    return aes.encrypt(plain)

def k_v_parser(in_str):
    tokens = in_str.split('&')
    parsed = {}
    for token in tokens:
        key, value = token.split('=')
        parsed[key] = value
    return parsed

def k_v_encoder(in_dict):
    encoded = []
    for key, value in in_dict.items():
        encoded.append(key+'='+value)
    return '&'.join(encoded)

def profile_for(email):
    email = ''.join(email.split('='))
    email = ''.join(email.split('&'))
    profile = {'email': email, 'uid': '10', 'role': 'user'}
    return k_v_encoder(profile)

def encrypt_profile(email):
    aes = AES.new(UNKNOWN_KEY, AES.MODE_ECB)
    plain = bytes(profile_for(email), 'utf-8')
    plain = pad(plain, AES.block_size)
    return aes.encrypt(plain)

def decrypt_profile(cipher):
    aes = AES.new(UNKNOWN_KEY, AES.MODE_ECB)
    plain = aes.decrypt(cipher)
    plain = unpad(plain, AES.block_size)
    return k_v_parser(plain.decode('utf-8'))

def cut_and_paste_attack(encrypt_func):
    block_size = AES.block_size
    """Assume the token is: 'email=<in>&uid=10&role=user'. Generate ciphertext
    such that the second block begins with admin and has appropriate PKCS#7
    padding, and the third block ends with '&role='"""
    fake_email = 'fooey@bar.'+'admin'+'\x0b'*11+'com'
    cipher = encrypt_func(fake_email)

    return cipher[:block_size]+cipher[2*block_size:3*block_size]+cipher[block_size:2*block_size]

class Set2(TestCase):

    def test_k_v_parser(self):
        expect = {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
        in_str = 'foo=bar&baz=qux&zap=zazzle'
        self.assertEqual(k_v_parser(in_str), expect)
        self.assertEqual(k_v_encoder(expect), in_str)

    def test_profile_for(self):
        expect = 'email=foo@bar.com&uid=10&role=user'
        self.assertEqual(profile_for('foo@bar.com'), expect)
        expect = 'email=foo@bar.comstuffstuff&uid=10&role=user'
        self.assertEqual(profile_for('foo@bar.com&stuff=stuff'), expect)

    # implement PKCS#7 padding
    def test_9(self):
        key = bytes('YELLOW SUBMARINE', 'utf-8')
        padded = bytes('YELLOW SUBMARINE\x04\x04\x04\x04', 'utf-8')
        self.assertEqual(cu.pad_PKCS7(key, block_size=20), padded)
        self.assertEqual(cu.pad_PKCS7(key, block_size=len(key)), key)

    # implement CBC mode
    def test_10(self):
        key = bytes('YELLOW SUBMARINE', 'utf-8')
        plain_expect = cu.read_utf8('data/Set_1_7_decrypted.txt')
        cipher = cu.read_base64('data/Set_2_10.txt')
        plain = cu.decrypt_AES_CBC(cipher, key)
        self.assertEqual(plain, plain_expect)
        recipher = cu.encrypt_AES_CBC(plain, key)
        self.assertEqual(recipher, cipher)

    # ECB/CBC oracle
    def test_11(self):
        num_shots = 1000
        ECB_detect = [cu.ECB_oracle(encryption_oracle) for _ in range(num_shots)]
        fraction_ECB = sum(ECB_detect)/len(ECB_detect)
        self.assertAlmostEqual(fraction_ECB, 0.5, delta=0.05)

    # byte-at-a-time ECB decryption (Simple)
    def test_12(self):
        block_size = cu.get_block_size(black_box)
        self.assertEqual(block_size, AES.block_size)
        self.assertTrue(cu.ECB_oracle(black_box, block_size=block_size))
        secret = cu.chosen_plaintext_ECB(black_box, block_size=block_size)
        self.assertEqual(secret, UNKNOWN_PLAIN)

    # ECB cut-and-paste
    def test_13(self):
        encrypted = cut_and_paste_attack(encrypt_profile)
        user_profile = decrypt_profile(encrypted)
        self.assertEqual(user_profile['role'], 'admin')
