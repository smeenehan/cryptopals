from math import inf

from Crypto.Cipher import AES

from .utils import random_bytes, single_bytes, XOR_bytes

"""Block ciphers, including stream ciphers implemented using CTR mode"""

def detect_ECB(cipher, block_size=AES.block_size):
    """Detect whether an encrypted ciphertext used ECB, by looking for
    repeated code blocks."""
    num_blocks = len(cipher)//block_size
    blocks = [cipher[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    return len(blocks) != len(set(blocks))

def ECB_oracle(encrypt_func, block_size=AES.block_size):
    """Return whether or not a specified black-box block-cipher encryption
    function is using ECB mode."""
    test = random_bytes(count=block_size)*100
    cipher = encrypt_func(test)
    return detect_ECB(cipher, block_size=block_size)

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

class AES_CTR(object):
    """Encrypt/decrypt using AES in CTR (stream) mode. Made into a class
    primarily so that it's easy to make a edit function that can adjust the
    internal counter."""

    def __init__(self, key, nonce=0):
        nonce_size = AES.block_size//2
        if isinstance(nonce, bytes):
            if len(nonce) != nonce_size:
                raise ValueError('nonce must be '+nonce_size+' bytes')
            self._nonce = nonce
        else:
            self._nonce = nonce.to_bytes(nonce_size, 'little')
        self._count = 0
        self._aes = AES.new(key, AES.MODE_ECB)

    def process(self, plain):
        step = AES.block_size
        offsets = range(0, len(plain), step)
        out_blocks = [self._process_block(plain[x:x+step]) for x in offsets]
        return b''.join(out_blocks)

    def reset(self):
        self._count = 0

    def edit(self, cipher, offset_block, new_plain_block):
        old_count = self._count
        offset = offset_block*AES.block_size
        new_cipher = bytearray(cipher)
        try:
            self._count = offset_block
            new_cipher_block = self.process(new_plain_block)
            new_cipher[offset:offset+len(new_cipher_block)] = new_cipher_block
        finally:
            self._count = old_count
        return new_cipher

    def _process_block(self, plain):
        in_bytes = self._nonce+self._count.to_bytes(AES.block_size//2, 'little')
        keystream = self._aes.encrypt(in_bytes)
        keystream = keystream[:len(plain)]
        self._count += 1
        return XOR_bytes(plain, keystream, repeat=False)

def find_diff_blocks(byte_1, byte_2, block_size):
    """Return list (in order) of which blocks differ between two byte-likes"""
    num_blocks = len(byte_1)//block_size
    blocks_1 = [byte_1[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    blocks_2 = [byte_2[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    return [x for x in range(num_blocks) if blocks_1[x] != blocks_2[x]]

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
