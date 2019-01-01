import base64
from collections import defaultdict
from Crypto.Cipher import AES
from itertools import cycle, combinations
from math import inf
from string import ascii_lowercase

# fractional frequency of different letters in the English language
letter_freqs = {
'a':0.08167, 'b':0.01492, 'c':0.02782, 'd':0.04253, 'e':0.12702,  'f':0.02228,
'g':0.02015, 'h':0.06094, 'i':0.06966, 'j':0.00153, 'k':0.00772, 'l':0.04025,
'm':0.02406, 'n':0.06749, 'o':0.07507, 'p':0.01929, 'q':0.00095, 'r':0.05987,
's':0.06327, 't':0.09056, 'u':0.02758, 'v':0.00978, 'w':0.02360, 'x':0.00150,
'y':0.01974, 'z':0.00074
}

single_bytes = [bytes([x]) for x in range(256)]

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def bytes_to_hex(in_bytes):
    return bytes.hex(in_bytes)

def base64_to_bytes(base64_string):
    return bytes(base64.b64decode(base64_string))

def bytes_to_base64(in_bytes):
    return base64.b64encode(in_bytes).decode('utf-8')

def hex_to_base64(hex_string):
    return bytes_to_base64(hex_to_bytes(hex_string))

def base64_to_hex(base64_string):
    return bytes_to_hex(base64_to_bytes(base64_string))

def read_base64(file_path):
    cipher = ''
    with open(file_path, 'r') as f:
        cipher = f.read().replace('\n', '')
    return base64_to_bytes(cipher)

def XOR_bytes(bytes_1, bytes_2):
    if len(bytes_1) >= len(bytes_2):
        return bytes([x^y for x, y in zip(bytes_1, cycle(bytes_2))])
    else:
        return bytes([x^y for x, y in zip(cycle(bytes_1), bytes_2)])

def probability_of_english(test_string):
    """Estimate probability that a given string is English-language based on
    letter frequency compared to typical English values, with a penalty for
    fraction of non-letter, non-whitespace characters."""
    test_string = test_string.replace(' ','').lower()
    num_occurrences = defaultdict(int)

    char_gen = (char for char in test_string if char in ascii_lowercase)
    for char in char_gen:
        num_occurrences[char] += 1
    num_chars = sum([x for x in num_occurrences.values()])

    penalty = len(test_string)-num_chars
    for char in ascii_lowercase:
        real_percent = num_occurrences[char]/num_chars if num_chars > 0 else 0
        penalty += num_chars*abs(real_percent-letter_freqs[char])
    penalty /= len(test_string)
    return 1.0-penalty

def decrypt_single_byte_XOR(cipher):
    """Brute-force decrypt English (UTF-8) text encrypted with single-byte XOR.

    Args:
        cipher (bytes-like): Encrypted text.
    Returns:
        probability (float): Estimated probability of English text
        plain (bytes-like): Decrypted plain-text
        key (bytes-like): Single-byte key
    """
    best_match = (0.0, None, None)
    for key in single_bytes:
        plain = XOR_bytes(cipher, key)
        try:
            probability = probability_of_english(plain.decode('utf-8'))
        except UnicodeDecodeError:
            pass
        else:
            if probability > best_match[0]:
                best_match = (probability, plain, key)
    return best_match

def Hamming_dist(bytes_1, bytes_2):
    return sum([bin(x^y).count('1') for x, y in zip(bytes_1, bytes_2)])

def decrypt_repeating_XOR(cipher, max_key_size=40):
    """Decrypt text encoded with repeating-key XOR (Vigenere cipher).

    Args:
        cipher (bytes-like): Encrypted text.
        max_key_size (int, optional): Maximum key-length to guess.
    Returns:
        plain (bytes-like): Decrypted plain-text
        key (bytes-like): Decryption key
    """
    key_size = guess_repeating_XOR_key_size(cipher, max_key_size=max_key_size)
    key = get_repeating_XOR_key(cipher, key_size)
    plain = XOR_bytes(cipher, key)
    return (plain, key)

def guess_repeating_XOR_key_size(cipher, max_key_size, num_to_avg=4):
    """Guess key size for repeating-key XOR (Vigenere cipher) by comparing
    average Hamming distance of multiple blocks of the ciphertext."""
    min_dist = inf
    for size in range(1, max_key_size+1):
        num_blocks = min(num_to_avg, len(cipher)//size)
        blocks = [cipher[x*size:(x+1)*size] for x in range(num_blocks)]
        distances = [Hamming_dist(x,y)/size for x, y in combinations(blocks, 2)]
        avg_dist = sum(distances)/len(distances)
        if avg_dist < min_dist:
            min_dist, key_size = avg_dist, size
    return key_size

def get_repeating_XOR_key(cipher, key_size):
    key = []
    for block in transpose_bytes(cipher, key_size):
        key_byte = decrypt_single_byte_XOR(block)[2][0]
        key.append(key_byte)
    return bytes(key)

def transpose_bytes(in_bytes, block_size):
    """Generator yielding subsets of a byte-like, where the n-th generated
    value is every n-th byte from repeated blocks of the input."""
    num_blocks = len(in_bytes)//block_size
    for offset in range(block_size):
        yield bytes([in_bytes[x*block_size+offset] for x in range(num_blocks)])

def detect_AES_ECB(cipher):
    """Detect whether an AES encrypted ciphertext used ECB, by looking for
    repeated code blocks."""
    block_size = AES.block_size
    num_blocks = len(cipher)//block_size
    blocks = [cipher[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    return len(blocks) != len(set(blocks))
