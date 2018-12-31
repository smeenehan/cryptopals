import crypto_utils as cu
from unittest import TestCase

class Set1(TestCase):

    def test_byte_to_hex_conversion(self):
        hex_string = '2ef0'
        byte_array = bytearray([46, 240])
        self.assertEqual(cu.hex_to_bytes(hex_string), byte_array)
        self.assertEqual(cu.bytes_to_hex(byte_array), hex_string)

    def test_byte_to_base64_conversion(self):
        base64_string = 'SGVsbG8='
        byte_array = bytearray([72, 101, 108, 108, 111])
        self.assertEqual(cu.base64_to_bytes(base64_string), byte_array)
        self.assertEqual(cu.bytes_to_base64(byte_array), base64_string)

    def test_1(self):
        hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        base64_string = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        self.assertEqual(cu.hex_to_base64(hex_string), base64_string)
