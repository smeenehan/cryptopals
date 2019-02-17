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
UNKNOWN_PREFIX = cu.random_bytes(randint(0, 24))

UNKNOWN_KEY_TWO = cu.random_bytes()
UNKNOWN_IV = cu.random_bytes()
UNKNOWN_NONCE = cu.random_bytes(count=AES.block_size//2)
PREFIX_TWO = b'comment1=cooking%20MCs;userdata='
SUFFIX_TWO = b';comment2=%20like%20a%20pound%20of%20bacon'

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
    plain = UNKNOWN_PREFIX+plain+UNKNOWN_PLAIN
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
    fake_email = 'fooey@bar.'+'admin'+'\x0b'*(block_size-5)+'com'
    cipher = encrypt_func(fake_email)

    return cipher[:block_size]+cipher[2*block_size:3*block_size]+cipher[block_size:2*block_size]

def encrypt16(plain, alter_invalid=True, CTR=False):
    if alter_invalid:
        plain = plain.replace(b';', b'?')
        plain = plain.replace(b'=', b'?')
    plain = PREFIX_TWO+plain+SUFFIX_TWO
    if CTR:
        return cu.AES_CTR(UNKNOWN_KEY, nonce=UNKNOWN_NONCE).process(plain)
    else:
        return cu.encrypt_AES_CBC(plain, UNKNOWN_KEY_TWO, iv=UNKNOWN_IV)

def decrypt16(cipher, CTR=False):
    if CTR:
        plain = cu.AES_CTR(UNKNOWN_KEY, nonce=UNKNOWN_NONCE).process(cipher)
    else:
        plain = cu.decrypt_AES_CBC(cipher, UNKNOWN_KEY_TWO, iv=UNKNOWN_IV)
    tokenized = plain.split(b';')
    for token in tokenized:
        parts = token.split(b'=')
        if parts[0] == b'admin':
            return True
    return False

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

    def test_diff_blocks(self):
        block_size = randint(5, 20)
        byte_1 = cu.random_bytes(10*block_size)
        byte_2 = bytearray(byte_1)
        byte_2[2*block_size:3*block_size] = cu.random_bytes(block_size)
        byte_2[7*block_size:8*block_size] = cu.random_bytes(block_size)
        diff_blocks = cu.find_diff_blocks(byte_1, byte_2, block_size)
        self.assertEqual(diff_blocks, [2, 7])

    def test_find_prefix_len(self):
        self.assertEqual(cu.find_prefix_len(black_box, AES.block_size),
                         len(UNKNOWN_PREFIX))

    def test_black_box_16(self):
        plain = b';admin=True'
        cipher = encrypt16(plain, alter_invalid=False)
        self.assertTrue(decrypt16(cipher))
        cipher = encrypt16(plain)
        self.assertFalse(decrypt16(cipher))

    # implement PKCS#7 padding
    def test_9(self):
        key = b'YELLOW SUBMARINE'
        padded = b'YELLOW SUBMARINE\x04\x04\x04\x04'
        self.assertEqual(cu.pad_PKCS7(key, block_size=20), padded)
        self.assertEqual(cu.pad_PKCS7(key, block_size=len(key)),
                         key+bytes([len(key)])*len(key))

    # implement CBC mode
    def test_10(self):
        key = b'YELLOW SUBMARINE'
        plain_expect = cu.read_utf8('data/Set_1_7_decrypted.txt')
        cipher = cu.read_base64('data/Set_2_10.txt')
        plain = cu.decrypt_AES_CBC(cipher, key)
        self.assertEqual(plain, plain_expect)
        plain = cu.unpad_PKCS7(plain)
        recipher = cu.encrypt_AES_CBC(plain, key)
        self.assertEqual(recipher, cipher)

    # ECB/CBC oracle
    def test_11(self):
        num_shots = 1000
        ECB_detect = [cu.ECB_oracle(encryption_oracle) for _ in range(num_shots)]
        fraction_ECB = sum(ECB_detect)/len(ECB_detect)
        self.assertAlmostEqual(fraction_ECB, 0.5, delta=0.05)

    # byte-at-a-time ECB decryption (Simple and Hard)
    def test_12(self):
        block_size = cu.get_block_size(black_box)
        self.assertEqual(block_size, AES.block_size)
        self.assertTrue(cu.ECB_oracle(black_box, block_size=block_size))
        secret = cu.chosen_plaintext_ECB(black_box, block_size=block_size)
        secret = cu.unpad_PKCS7(secret)
        self.assertEqual(secret, UNKNOWN_PLAIN)

    # ECB cut-and-paste
    def test_13(self):
        encrypted = cut_and_paste_attack(encrypt_profile)
        user_profile = decrypt_profile(encrypted)
        self.assertEqual(user_profile['role'], 'admin')

    # PKCS#7 padding validation
    def test_15(self):
        good_padding = b'ICE ICE BABY\x04\x04\x04\x04'
        good_padding_2 = b'ICE ICE BABY\x04\x03\x02\x01'
        good_padding_3 = b'YELLOW SUBMARINE'+bytes([16])*16
        bad_padding = b'ICE ICE BABY\x05\x05\x05\x05'
        bad_padding_2 = b'ICE ICE BABY\x01\x02\x03\x04'
        bad_padding_3 = b'YELLOW SUBMARINE'

        self.assertEqual(cu.unpad_PKCS7(good_padding), b'ICE ICE BABY')
        self.assertEqual(cu.unpad_PKCS7(good_padding_2), b'ICE ICE BABY\x04\x03\x02')
        self.assertEqual(cu.unpad_PKCS7(good_padding_3), b'YELLOW SUBMARINE')
        self.assertRaises(ValueError, cu.unpad_PKCS7, bad_padding)
        self.assertRaises(ValueError, cu.unpad_PKCS7, bad_padding_2)
        self.assertRaises(ValueError, cu.unpad_PKCS7, bad_padding_3)

    # CBC bitflipping attack
    def test_16(self):
        """Assume that we know the prefix length is exactly 32 bytes
        (2 blocks). Assume also that we know ';' and '=' are changed to
        '?'. No clue how to do this otherwise..."""
        plain = b';admin=True'
        cipher = bytearray(encrypt16(plain))
        cipher[16] = cu.XOR_bytes(b'?', cu.XOR_bytes(bytes([cipher[16]]), b';'))[0]
        cipher[22] = cu.XOR_bytes(b'?', cu.XOR_bytes(bytes([cipher[22]]), b'='))[0]
        self.assertTrue(decrypt16(cipher))

