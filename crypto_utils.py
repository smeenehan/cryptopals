import base64
from collections import defaultdict
from itertools import cycle
from string import ascii_lowercase

# fractional frequency of different letters in the English language
letter_freqs = {
'a':0.08167, 'b':0.01492, 'c':0.02782, 'd':0.04253, 'e':0.12702,  'f':0.02228,
'g':0.02015, 'h':0.06094, 'i':0.06966, 'j':0.00153, 'k':0.00772, 'l':0.04025,
'm':0.02406, 'n':0.06749, 'o':0.07507, 'p':0.01929, 'q':0.00095, 'r':0.05987,
's':0.06327, 't':0.09056, 'u':0.02758, 'v':0.00978, 'w':0.02360, 'x':0.00150,
'y':0.01974, 'z':0.00074
}

single_bytes = [bytearray([x]) for x in range(256)]

def hex_to_bytes(hex_string):
    return bytearray.fromhex(hex_string)

def bytes_to_hex(byte_array):
    return bytearray.hex(byte_array)

def base64_to_bytes(base64_string):
    return bytearray(base64.b64decode(base64_string))

def bytes_to_base64(byte_array):
    return base64.b64encode(byte_array).decode('utf-8')

def hex_to_base64(hex_string):
    return bytes_to_base64(hex_to_bytes(hex_string))

def base64_to_hex(base64_string):
    return bytes_to_hex(base64_to_bytes(base64_string))

def XOR_bytes(bytes_1, bytes_2):
    if len(bytes_1) >= len(bytes_2):
        return bytearray([x^y for x, y in zip(bytes_1, cycle(bytes_2))])
    else:
        return bytearray([x^y for x, y in zip(cycle(bytes_1), bytes_2)])

def probability_of_english(test_string):
    """Estimate the probability that a given string is English-language
    by comparing frequencies of ASCII letters to typical English values"""
    test_string = test_string.replace(" ","").lower()
    num_occurrences = defaultdict(int)

    char_gen = (char for char in test_string if char in ascii_lowercase)
    for char in char_gen:
        num_occurrences[char] += 1
    num_chars = sum([x for x in num_occurrences.values()])

    score = len(test_string)-num_chars # penalty for non-English characters
    for char in ascii_lowercase:
        real_percent = num_occurrences[char]/num_chars if num_chars > 0 else 0
        score += num_chars*abs(real_percent-letter_freqs[char])
    return 1.0-score/len(test_string)

def single_byte_XOR(cipher_bytes):
    """XOR a given set of bytes with all possible single-byte keys, return
    the most probable English result as a tuple:
    (probability, plain-text bytes, single-byte key)"""
    best_match = (0.0, None, None)
    for byte in single_bytes:
        plain_bytes = XOR_bytes(cipher_bytes, byte)
        try:
            probability = probability_of_english(plain_bytes.decode('utf-8'))
        except UnicodeDecodeError:
            pass
        else:
            if probability > best_match[0]:
                best_match = (probability,plain_bytes,byte)
    return best_match
