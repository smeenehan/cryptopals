from datetime import datetime
from random import choice, randint
from statistics import median
from string import printable
from time import perf_counter
from unittest import TestCase

from Crypto.Cipher import AES

import crypto.block as cb
import crypto.hash as ch
import crypto.utils as cu
import set4_server as server
from test_set2 import encrypt16, decrypt16

SECRET_KEY = cu.random_bytes(count=randint(4, 32))

def encrypt27():
    key = cu.random_bytes()
    plain = b"For you to even touch my skill, you gotta put the one killer bee and he ain't gonna kill"
    return cb.encrypt_AES_CBC(plain, key, iv=key), key

def decrypt27(cipher, key):
    plain = cb.decrypt_AES_CBC(cipher, key, iv=key)
    if not all([x>31 and x<128 for x in plain]):
        raise ValueError(plain)

def key_MAC(message, algo):
    key_message = SECRET_KEY+message
    if algo == 'SHA1':
        return ch.SHA1(key_message)
    elif algo == 'MD4':
        return ch.MD4(key_message)
    else:
        raise ValueError('Unknown hash algorithm: '+algo)

def authenticate_MAC(message, MAC, algo):
    return MAC==key_MAC(message, algo)

class Set4(TestCase):

    def test_ctr_edit(self):
        plain = cu.random_bytes(count=10*AES.block_size)
        key = cu.random_bytes()
        nonce = cu.random_bytes(count=AES.block_size//2)
        ctr = cb.AES_CTR(key, nonce=nonce)
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
        messages = [
        b'The quick brown fox jumps over the lazy dog',
        b'The quick brown fox jumps over the lazy cog',
        b'']
        digests = [
        cu.hex_to_bytes('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12'),
        cu.hex_to_bytes('de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3'),
        cu.hex_to_bytes('da39a3ee5e6b4b0d3255bfef95601890afd80709')]
        self.assertTrue(all([ch.SHA1(m)==d for m, d in zip(messages, digests)]))

    def test_md4(self):
        messages = [
        b'',
        b'a',
        b'abc',
        b'message digest',
        b'abcdefghijklmnopqrstuvwxyz',
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        b'12345678901234567890123456789012345678901234567890123456789012345678901234567890']
        digests = [
        cu.hex_to_bytes('31d6cfe0d16ae931b73c59d7e0c089c0'),
        cu.hex_to_bytes('bde52cb31de33e46245e05fbdbd6fb24'),
        cu.hex_to_bytes('a448017aaf21d8525fc10ae87aa6729d'),
        cu.hex_to_bytes('d9130a8164549fe818874806e1c7014b'),
        cu.hex_to_bytes('d79e1c308aa5bbcdeea8ed63df412da9'),
        cu.hex_to_bytes('043f8582f241db351ce627e153e7f0e4'),
        cu.hex_to_bytes('e33b4ddc9c38f2199c3e7b164fcc0536')]
        self.assertTrue(all([ch.MD4(m)==d for m, d in zip(messages, digests)]))

    def test_hmac(self):
        keys = [b'', b'key']
        messages = [b'', b'The quick brown fox jumps over the lazy dog']
        digests = [
        cu.hex_to_bytes('fbdb1d1b18aa6c08324b7d64b71fb76370690e1d'),
        cu.hex_to_bytes('de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9')]
        self.assertTrue(
            all([ch.HMAC(k, m)==d for k, m, d in zip(keys, messages, digests)]))

    # Break "random access read/write" CTR
    def test_25(self):
        key = cu.random_bytes()
        nonce = cu.random_bytes(count=AES.block_size//2)
        plain = cu.read_base64('data/Set_1_7.txt')
        ctr = cb.AES_CTR(key, nonce=nonce)
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

    # Break SHA-1 keyed MAC using length extension
    def test_29(self):
        orig_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
        orig_MAC = key_MAC(orig_message, 'SHA1')

        new_end = b';admin=true'
        state = [int.from_bytes(x, 'big') for x in cu.to_chunks(orig_MAC, 4)]

        accepted = []
        for key_len_guess in range(33):
            orig_pad = ch.MD_padding(bytes(key_len_guess)+orig_message, 512)
            new_message = orig_message+orig_pad+new_end
            new_pad = ch.MD_padding(bytes(key_len_guess)+new_message, 512)
            guess_MAC = ch.SHA1(new_end+new_pad, init=state, do_pad=False)
            accepted.append(authenticate_MAC(new_message, guess_MAC, 'SHA1'))

        self.assertTrue(any(accepted))

    # Break MD4 keyed MAC using length extension
    def test_30(self):
        orig_message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
        orig_MAC = key_MAC(orig_message, 'MD4')

        new_end = b';admin=true'
        state = [int.from_bytes(x, 'little') for x in cu.to_chunks(orig_MAC, 4)]

        accepted = []
        for key_len_guess in range(33):
            orig_pad = ch.MD_padding(bytes(key_len_guess)+orig_message, 512, byteorder='little')
            new_message = orig_message+orig_pad+new_end
            new_pad = ch.MD_padding(bytes(key_len_guess)+new_message, 512, byteorder='little')
            guess_MAC = ch.MD4(new_end+new_pad, init=state, do_pad=False)
            accepted.append(authenticate_MAC(new_message, guess_MAC, 'MD4'))

        self.assertTrue(any(accepted))

class Set4Server(TestCase):

    def setUp(self):
        server.app.testing = True
        self.client = server.app.test_client()
        self.secret = server.SECRET_KEY

    def test_server(self):
        response = self.client.get('/')
        self.assertEqual(response.data, b'OK')
        self.assertEqual(response.status_code, 200)

    def test_hmac(self):
        file = 'foo'
        sig = cu.bytes_to_hex(ch.HMAC(self.secret, file.encode()))
        bad_sig = cu.bytes_to_hex(cu.random_bytes(count=20))
        good_get = f'/test?file={file}&signature={sig}'
        bad_get = f'/test?file={file}&signature={bad_sig}'
        response = self.client.get(good_get)
        self.assertEqual(response.status_code, 200)
        response = self.client.get(bad_get)
        self.assertEqual(response.status_code, 500)

    def test_31_32(self):

        def get_next_byte(known, file, rounds=10):
            suffix_len = server.HMAC_LEN-len(known)
            times = [[] for _ in range(256)]
            for idx in range(256):
                suffix = bytes([idx]+[0]*(suffix_len-1))
                sig = cu.bytes_to_hex(known+suffix)
                for _ in range(rounds):
                    init_time = perf_counter()
                    response = self.client.get(f'/test?file={file}&signature={sig}')
                    diff_time = perf_counter()-init_time
                    times[idx].append(diff_time)
            median_times = [median(x) for x in times]
            byte = max(range(256), key=lambda x: median_times[x])
            return bytes([byte])

        file = 'foo'
        known = b''
        while len(known)<server.HMAC_LEN:
            known += get_next_byte(known, file)
        known = cu.bytes_to_hex(known)
        response = self.client.get(f'/test?file={file}&signature={known}')
        self.assertEqual(response.status_code, 200)


