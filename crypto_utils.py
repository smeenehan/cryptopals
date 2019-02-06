import base64
from collections import defaultdict
from Crypto.Cipher import AES
from datetime import datetime
from itertools import cycle, combinations
from math import inf
from random import randint
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

def read_utf8(file_path):
    cipher = ''
    with open(file_path, 'r') as f:
        cipher = bytes(f.read(), 'utf-8')
    return cipher

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

def detect_ECB(cipher, block_size = AES.block_size):
    """Detect whether an encrypted ciphertext used ECB, by looking for
    repeated code blocks."""
    num_blocks = len(cipher)//block_size
    blocks = [cipher[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    return len(blocks) != len(set(blocks))

def pad_PKCS7(unpadded, block_size=AES.block_size):
    """Pad to given block size according to PKCS#7 standard"""
    mod_len = len(unpadded)%block_size
    num_bytes_needed = block_size-mod_len
    padding = bytes([num_bytes_needed]*num_bytes_needed)
    return unpadded+padding

def unpad_PKCS7(padded, block_size=AES.block_size):
    """Unpad according to PKCS#7 standard. Raises ValueError if string has
    invalid padding"""
    padding_bytes = [x for x in range(1, block_size)]
    last_byte = padded[-1]
    if last_byte>0 and last_byte<=block_size:
        test_pad = padded[-last_byte:]
        if set(test_pad)=={last_byte}:
            return padded[:-last_byte]
    raise ValueError('Invalid PKCS#7 padding detected')

def decrypt_AES_CBC(cipher, key, iv=None):
    block_size = AES.block_size
    if iv is None:
        iv = bytes([0]*block_size)
    aes = AES.new(key, AES.MODE_ECB)
    num_blocks = len(cipher)//block_size

    plain = bytearray([])
    for idx in range(num_blocks):
        cipher_block = cipher[idx*block_size:(idx+1)*block_size]
        plain_block = aes.decrypt(cipher_block)
        plain += XOR_bytes(plain_block, iv)
        iv = cipher_block
    return bytes(plain)

def encrypt_AES_CBC(plain, key, iv=None):
    block_size = AES.block_size
    if iv is None:
        iv = bytes([0]*block_size)
    aes = AES.new(key, AES.MODE_ECB)
    plain = pad_PKCS7(plain)
    num_blocks = len(plain)//block_size

    cipher = bytearray([])
    for idx in range(num_blocks):
        plain_block = XOR_bytes(plain[idx*block_size:(idx+1)*block_size], iv)
        cipher_block = aes.encrypt(plain_block)
        cipher += cipher_block
        iv = cipher_block
    return bytes(cipher)

def random_bytes(count=AES.block_size):
    return bytes([randint(0, 255) for _ in range(count)])

def ECB_oracle(encrypt_func, block_size=AES.block_size):
    """Return whether or not a specified black-box block-cipher encryption
    function is using ECB mode."""
    test = random_bytes(count=block_size)*100
    cipher = encrypt_func(test)
    return detect_ECB(cipher, block_size=block_size)

def get_block_size(encrypt_func):
    """Find block size used by a black-box, block-cipher encryption function."""
    last_len, first_len, second_len = len(encrypt_func(bytes([]))), 0, 0
    in_size = 1
    while second_len == 0:
        in_bytes = bytes([0]*in_size)
        cipher_len = len(encrypt_func(in_bytes))
        in_size += 1
        if cipher_len == last_len:
            continue
        if first_len == 0:
            first_len = cipher_len
            last_len = first_len
        else:
            second_len = cipher_len
    return second_len-first_len

def chosen_plaintext_ECB(encrypt_func, block_size=AES.block_size):
    """Determine a secret plaintext used by a black-box, block-cipher
    encryption function operating in ECB mode. The only requirement is that
    the function appends arbitrary, user-supplied input to the secret prior
    to encryption, and uses the same secret/key for each query."""

    # Determine if there is a prefix applied by the function, get relevant offsets
    pre_len = find_prefix_len(encrypt_func, block_size)
    num_extra_pad = block_size-pre_len%block_size if pre_len > 0 else 0
    pre_idx = (pre_len+num_extra_pad)//block_size
    def determine_padding(known):
        """Given current knowledge, determine input length so that next unknown
        byte will be aligned on the last byte of a block, get the offset index
        of that block, and get the first N-1 input bytes of that block."""
        pad_size = num_extra_pad+block_size-1-len(known)%block_size
        in_bytes = bytes([0]*pad_size)
        idx = pre_idx+len(known)//block_size
        total = in_bytes+bytes(known)
        last_frag = bytes([0]*num_extra_pad)+total[-block_size+1:]
        return (in_bytes, idx, last_frag)

    def get_block(cipher, idx):
        return cipher[idx*block_size:(idx+1)*block_size]

    secret = bytearray([])
    remaining = inf
    while remaining > 0:
        in_bytes, idx, last_frag = determine_padding(secret)
        cipher_frags = [get_block(encrypt_func(last_frag+x), pre_idx) for x in single_bytes]
        plain_dict = {x: y[0] for x, y in zip(cipher_frags, single_bytes)}
        cipher = encrypt_func(in_bytes)
        cipher_frag = get_block(cipher, idx)
        secret.append(plain_dict[cipher_frag])
        remaining = len(cipher)-len(in_bytes)-len(secret)-pre_len
    return bytes(secret)

def find_prefix_len(encrypt_func, block_size):
    """For an arbitrary black-box encryption function operating in ECB mode, which
    may append an unknown, fixed-length byte array to the submitted plain-text,
    determine the length of this uknown prefix."""
    for num in range(1, block_size+2):
        byte_1 = encrypt_func(bytes([0]*num))
        byte_2 = encrypt_func(bytes([1]*num))
        diff_list = find_diff_blocks(byte_1, byte_2, block_size)
        if len(diff_list) > 1:
            return (diff_list[0]+1)*block_size-num+1
    return 0

def find_diff_blocks(byte_1, byte_2, block_size):
    """Return list (in order) of which blocks differ between two byte-likes"""
    num_blocks = len(byte_1)//block_size
    blocks_1 = [byte_1[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    blocks_2 = [byte_2[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    return [x for x in range(num_blocks) if blocks_1[x] != blocks_2[x]]

def decrypt_CBC_padding_oracle(cipher, oracle, block_size=AES.block_size):
    """Decrypt a cipher text, encrypted with CBC, given an oracle function that
    will take a ciphertext as input and return True or False depending on whether
    the decrypted plaintext has valid PKCS#7 padding.

    For simplicity, I'm assuming the IV is prepended to the ciphertext, though this
    is not strictly necessary. We just need to know what it is."""
    known_blocks = []
    num_blocks = len(cipher)//block_size

    def prepare_attack_block(mod_cipher, known):
        """Figure out which byte we need to twiddle in the ciphertext, and prepare
        the rest of the second-to-last block so we'll get the right padding."""
        num_known = len(known)
        pad_byte = num_known+1
        to_twiddle = -block_size-num_known-1
        if num_known>0:
            known_cipher = mod_cipher[to_twiddle+1:-block_size]
            alter = XOR_bytes(XOR_bytes(known_cipher, known),
                              bytes([pad_byte])*num_known)
            mod_cipher[to_twiddle+1:-block_size] = alter
        return to_twiddle, pad_byte

    def decrypt_next_byte(mod_cipher, known):
        """Given the cipher text, up to block N, and existing known plaintext
        from the end of block N, decrypt the next byte starting from the end, and
        return the new known plain (one byte longer)"""
        byte_to_twiddle, pad_byte = prepare_attack_block(mod_cipher, known)
        orig_cipher = mod_cipher[byte_to_twiddle]
        new_cipher = 0
        for x in range(256):
            mod_cipher[byte_to_twiddle] = x
            if oracle(mod_cipher) == True:
                new_cipher = x
                break;
        new_known = (orig_cipher^new_cipher)^pad_byte
        return bytes([new_known])+known

    for idx in range(num_blocks-1):
        known = bytes([])
        for jdx in range(block_size):
            mod_cipher = bytearray(cipher[:len(cipher)-idx*block_size])
            known = decrypt_next_byte(mod_cipher, known)
        known_blocks.append(known)
    return b''.join([x for x in reversed(known_blocks)])

def AES_CTR_stream(key, nonce_val=0):
    nonce = nonce_val.to_bytes(AES.block_size//2, 'little')
    count = 0
    aes = AES.new(key, AES.MODE_ECB)

    def streamer(plain):
        nonlocal count
        in_bytes = nonce+count.to_bytes(AES.block_size//2, 'little')
        keystream = aes.encrypt(in_bytes)
        keystream = keystream[:len(plain)]
        cipher = XOR_bytes(plain, keystream)
        count += 1
        return cipher

    return streamer

def AES_CTR(in_bytes, key, nonce_val=0):
    stream = AES_CTR_stream(key, nonce_val=nonce_val)
    out_blocks = []
    for x in range(0, len(in_bytes), AES.block_size):
        out = stream(in_bytes[x:x+AES.block_size])
        out_blocks.append(out)
    return b''.join(out_blocks)

def MT19937_gen(seed=None):
    """Return a generator for random numbers using the 32-bit Mersenne Twister
    algorithm. The seed can be any integer, defaulting to the current POSIX
    timestamp if left default.

    Alternatively, the seed may a list containing a full 624 element internal state,
    which will be twisted prior to the first output."""
    if seed is None:
        seed = int(datetime.now().totimestamp())
    w, n, m, r = 32, 624, 397, 31

    if isinstance(seed, list):
        if len(seed) != n:
            raise ValueError('seed must be integer or 624-element list of integers')
        gen_state = seed
    else:
        gen_state = [seed]
        for idx in range(n-1):
            prev_val = gen_state[idx]
            next_val = 1812433253*(prev_val^(prev_val >> w-2))+idx+1
            next_val &= 0xffffffff # wrap to 32 bits
            gen_state.append(next_val)

    upper_mask = 0x80000000
    lower_mask = 0x7fffffff
    mt_ctr = n

    while True:
        if mt_ctr >= n:
            # twisting
            for idx in range(n):
                x = (gen_state[idx] & upper_mask) | (gen_state[(idx+1)%n] & lower_mask)
                xA = x >> 1
                if x%2 != 0:
                    xA ^= 0x9908B0DF
                gen_state[idx] = gen_state[(idx+m)%n]^xA
            mt_ctr = 0

        x = gen_state[mt_ctr]
        mt_ctr += 1

        x = MT19937_temper(x)
        yield x

def MT19937_temper(x):
    x ^= (x >> 11)
    x ^= (x << 7) & 0x9d2c5680
    x ^= (x << 15) & 0xefc60000
    x ^= (x >> 18)
    return x

def MT19937_untemper(x):
    # the last two steps of tempering happen to be self-inverses
    x ^= (x >> 18)
    x ^= (x << 15) & 0xefc60000

    # undo x ^= (x << 7) & 0x9d2c5680
    x ^= (x & 0x0012082d) << 7
    x ^= (x & 0x01001080) << 7
    x ^= (x & 0x00084000) << 7
    x ^= (x & 0x00200000) << 7

    # undo x ^= (x >> 11)
    x ^= (x & 0xffe00000) >> 11
    x ^= (x & 0x001ff800) >> 11
    return x

def MT19937_cipher(in_bytes, key):
    keystream = MT19937_gen(seed=key)
    out_bytes = bytearray([])
    shift_masks = [(24, 0xff000000), (16, 0x00ff0000),
                   (8, 0x0000ff00), (0, 0x000000ff)]
    for idx, plain_byte in enumerate(in_bytes):
        shift_index = idx%4
        if shift_index == 0:
            key_bytes = next(keystream)
        shift, mask = shift_masks[shift_index]
        key_byte = (key_bytes & mask) >> shift
        out_bytes.append(plain_byte^key_byte)
    return out_bytes
