import crypto_utils as cu
from Crypto.Cipher import AES
from unittest import TestCase

class Set1(TestCase):

    # Utilities tests
    def test_byte_to_hex_conversion(self):
        hex_string = '2ef0'
        byte_array = bytes([46, 240])
        self.assertEqual(cu.hex_to_bytes(hex_string), byte_array)
        self.assertEqual(cu.bytes_to_hex(byte_array), hex_string)

    def test_byte_to_base64_conversion(self):
        base64_string = 'SGVsbG8='
        byte_array = bytes([72, 101, 108, 108, 111])
        self.assertEqual(cu.base64_to_bytes(base64_string), byte_array)
        self.assertEqual(cu.bytes_to_base64(byte_array), base64_string)

    def test_Hamming(self):
        bytes_1 = bytes('this is a test', 'utf-8')
        bytes_2 = bytes('wokka wokka!!!', 'utf-8')
        self.assertEqual(cu.Hamming_dist(bytes_1, bytes_2), 37)

    # Convert hex to base 64
    def test_1(self):
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        base64_string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(cu.hex_to_base64(hex_string), base64_string)

    # Fixed XOR
    def test_2(self):
        bytes_1 = cu.hex_to_bytes('1c0111001f010100061a024b53535009181c')
        bytes_2 = cu.hex_to_bytes('686974207468652062756c6c277320657965')
        bytes_result = cu.hex_to_bytes('746865206b696420646f6e277420706c6179')
        self.assertEqual(cu.XOR_bytes(bytes_1, bytes_2), bytes_result)

    # single-byte XOR cipher
    def test_3(self):
        cipher = cu.hex_to_bytes('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
        plain_text = "Cooking MC's like a pound of bacon"
        key_byte = 88
        _, plain, key = cu.decrypt_single_byte_XOR(cipher)
        self.assertEqual(plain.decode('utf-8'), plain_text)
        self.assertEqual(key[0], key_byte)

    # detect single-character XOR
    def test_4(self):
        plain_expect = 'Now that the party is jumping\n'
        best_prob, best_plain = 0, ''
        with open('data/Set_1_4.txt', 'r') as f:
            for line in f:
                cipher = cu.hex_to_bytes(line)
                prob, plain, _ = cu.decrypt_single_byte_XOR(cipher)
                if prob > best_prob:
                    best_prob = prob
                    best_plain = plain.decode('utf-8')
        self.assertEqual(best_plain, plain_expect)

    # implement repeating-key XOR
    def test_5(self):
        plain_bytes = bytes("Burning 'em, if you ain't quick and nimble\n" \
                           +'I go crazy when I hear a cymbal', 'utf-8')
        key_bytes = bytes('ICE', 'utf-8')
        expected_bytes = cu.hex_to_bytes(
            '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324' \
           +'272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b202831652' \
           +'86326302e27282f')
        cipher_bytes = cu.XOR_bytes(plain_bytes, key_bytes)
        self.assertEqual(cipher_bytes, expected_bytes)

    # break repeating-key XOR
    def test_6(self):
        key_expect = bytes('Terminator X: Bring the noise', 'utf-8')
        plain_expect = cu.read_utf8('data/Set_1_6_decrypted.txt')
        cipher = cu.read_base64('data/Set_1_6.txt')
        (plain, key) = cu.decrypt_repeating_XOR(cipher)

        self.assertEqual(key, key_expect)
        self.assertEqual(plain, plain_expect)

    # AES in ECB mode
    def test_7(self):
        key = bytes('YELLOW SUBMARINE', 'utf-8')
        plain_expect = cu.read_utf8('data/Set_1_7_decrypted.txt')
        cipher = cu.read_base64('data/Set_1_7.txt')
        aes = AES.new(key, AES.MODE_ECB)
        plain = aes.decrypt(cipher)
        self.assertEqual(plain, plain_expect)

    # detect AES in ECB mode
    def test_8(self):
        ECB_ciphers = []
        with open('data/Set_1_8.txt', 'r') as f:
            for cipher in f:
                if cu.detect_ECB(cipher):
                    ECB_ciphers.append(cipher)
        self.assertEqual(len(ECB_ciphers), 1)
