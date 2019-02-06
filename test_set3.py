import crypto_utils as cu
from Crypto.Cipher import AES
from datetime import datetime
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

def simulate_random_seed():
    current_time = int(datetime.now().timestamp())
    current_time += randint(40, 1000)
    gen = cu.MT19937_gen(seed=current_time)
    timestamp = current_time+randint(40, 1000)
    rng_out = gen.__next__()
    return current_time, rng_out, timestamp

def random_stream_encrypt(known):
    prefix_num = randint(10, 50)
    prefix = cu.random_bytes(count=prefix_num)
    plain = prefix+known
    key = randint(0, 0xffff)
    cipher = cu.MT19937_cipher(plain, key)
    return cipher, key

def pw_token_gen():
    current_time = int(datetime.now().timestamp())
    return next(cu.MT19937_gen(seed=current_time))

def is_token_from_RNG(token):
    return token == pw_token_gen()

class Set3(TestCase):

    def test_pad_oracle(self):
        self.assertTrue(pad_check(encrypt_random()))

    def test_untemper(self):
        x = randint(0, 0xffffffff)
        tempered_x = cu.MT19937_temper(x)
        self.assertEqual(x, cu.MT19937_untemper(tempered_x))

    def test_stream_cipher(self):
        key = 0x59df
        plain = b"Recognize I'm a fool and you love me!"
        encrypted = cu.MT19937_cipher(plain, key)
        decrypted = cu.MT19937_cipher(encrypted, key)
        self.assertEqual(plain, decrypted)

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

    def test_22(self):
        """Given the output of the MT19937 RNG, assume we know this is the first
        output and that the RNG was seeded with the timestamp sometime within the
        last ~30 minutes. Then, we can just enumerate all possibilities."""
        real_seed, rng_out, timestamp = simulate_random_seed()
        for idx in range(0, 2000):
            test_seed = timestamp-idx
            test_gen = cu.MT19937_gen(seed=test_seed)
            if next(test_gen) == rng_out:
                break
        self.assertEqual(test_seed, real_seed)

    def test_23(self):
        rand_gen = cu.MT19937_gen(seed=int(datetime.now().timestamp()))
        rand_state = []
        for _, rand_out in zip(range(624), rand_gen):
            rand_state.append(cu.MT19937_untemper(rand_out))
        new_gen = cu.MT19937_gen(seed=rand_state)
        for _ in range(1000):
            self.assertEqual(next(rand_gen), next(new_gen))

    def test_24a(self):
        known = b'Hey, Dirty! Baby, I got your money'
        cipher, key = random_stream_encrypt(known)

        # ain't no force like brute force...
        for test_key in range(0xffff):
            test_plain = cu.MT19937_cipher(cipher, test_key)
            if test_plain[-len(known):] == known:
                break
        self.assertEqual(test_key, key)

    def test_24b(self):
        pw_token = pw_token_gen()
        self.assertTrue(is_token_from_RNG(pw_token))
