from secrets import randbelow
from unittest import TestCase

import crypto.key_exchange as ck

def get_message_recovery_oracle():
    public, private = ck.gen_RSA_keys()
    previous = []
    def oracle(cipher):
        if cipher in previous:
            raise ValueError('Ciphertext previously submitted')
        previous.append(cipher)
        return ck.cipher_RSA(cipher, private)
    return public, oracle

class Set6(TestCase):

    def test_message_recovery_oracle(self):
        public, oracle = get_message_recovery_oracle()

        plain = randbelow(2**64)
        cipher = ck.cipher_RSA(plain, public)
        decipher = oracle(cipher)
        self.assertEqual(plain, decipher)
        self.assertRaises(ValueError, oracle, cipher)

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
