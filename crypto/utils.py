import base64
from itertools import cycle
from math import ceil
from random import randint

from Crypto.Cipher import AES

single_bytes = [bytes([x]) for x in range(256)]

def int_to_bytes(i):
    """Return an integer as a big-endian byte-like"""
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')

def mask_N(num_bits):
    """Integer bit mask for N bits"""
    return int('1'*num_bits, 2)

def bit_not(value, num_bits):
    """Bitwise NOT for unsigned integers (since Python ints are signed)"""
    return mask_N(num_bits)-value

def rot_left(value, count, num_bits):
    """Left circular shift of integer by count bits, wrapped to N bits.
    Only allowed for 0 < count < N"""
    if count<1 or count>num_bits-1:
        raise ValueError('Only supports circular shifts of 1-(N-1) bits')
    return ((value << count)  | (value >> (num_bits-count))) & mask_N(num_bits)

def rot_right(value, count, num_bits):
    """Right circular shift of integer by count bits, wrapped to N bits.
    Only allowed for 0 < count < N"""
    if count<1 or count>num_bits-1:
        raise ValueError('Only supports circular shifts of 1-(N-1) bits')
    return ((value >> count) | (value << (num_bits-count))) & mask_N(num_bits)

def to_chunks(in_bytes, chunk_size):
    """Split byte-like into a list of chunks of a specified size"""
    num_chunks = ceil(len(in_bytes)/chunk_size)
    return [in_bytes[x*chunk_size:(x+1)*chunk_size] for x in range(num_chunks)]

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

def XOR_bytes(bytes_1, bytes_2, repeat=True):
    """XOR two byte-like objects. If repeat==True, the shorter of the two
    sequences will be cycled until the longer sequence is exhausted"""
    if repeat == False:
        return bytes([x^y for x, y in zip(bytes_1, bytes_2)])
    if len(bytes_1) >= len(bytes_2):
        return bytes([x^y for x, y in zip(bytes_1, cycle(bytes_2))])
    else:
        return bytes([x^y for x, y in zip(cycle(bytes_1), bytes_2)])

def Hamming_dist(bytes_1, bytes_2):
    return sum([bin(x^y).count('1') for x, y in zip(bytes_1, bytes_2)])

def transpose_bytes(in_bytes, block_size):
    """Generator yielding subsets of a byte-like, where the n-th generated
    value is every n-th byte from repeated blocks of the input."""
    num_blocks = len(in_bytes)//block_size
    for offset in range(block_size):
        yield bytes([in_bytes[x*block_size+offset] for x in range(num_blocks)])

def random_bytes(count=AES.block_size):
    return bytes([randint(0, 255) for _ in range(count)])
