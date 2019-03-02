from itertools import cycle

from .utils import bit_not, to_chunks, rot_left

"""Hashing algorithms (e.g., SHA-1, MD4)"""

def SHA1(message, init=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
         do_pad=True):
    h0, h1, h2, h3, h4 = init

    if do_pad:
        m = message+MD_padding(message, 512)
    elif len(message)%64>0:
        raise ValueError('Message must be in 512-bit blocks to forgo padding')
    else:
        m = message
    m_chunks = to_chunks(m, 64)
    for chunk in m_chunks:
        words = _SHA1_chunk_to_words(chunk)
        a, b, c, d, e = h0, h1, h2, h3, h4
        for idx, word in enumerate(words):
            if idx < 20:
                f = (b & c) | (bit_not(b, 32) & d)
                k = 0x5a827999
            elif idx < 40:
                f = b^c^d
                k = 0x6ed9eba1
            elif idx < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8f1bbcdc
            else:
                f = b^c^d
                k = 0xca62c1d6
            temp = (rot_left(a, 5, 32)+f+e+k+word) % 2**32
            e, d, c, b, a = d, c, rot_left(b, 30, 32), a, temp

        h0 = (h0+a) % 2**32
        h1 = (h1+b) % 2**32
        h2 = (h2+c) % 2**32
        h3 = (h3+d) % 2**32
        h4 = (h4+e) % 2**32

    digest = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return digest.to_bytes(20, 'big')

def _SHA1_chunk_to_words(chunk):
    """Break 512-bit chunk into 16 32-bit big-endian words, and extend
    into 80 words using prescribed XOR sequence"""
    words = [int.from_bytes(x, 'big') for x in to_chunks(chunk, 4)]
    for idx in range(16, 80):
        new_word = words[idx-3]^words[idx-8]^words[idx-14]^words[idx-16]
        new_word = rot_left(new_word, 1, 32)
        words.append(new_word)
    return words

def MD_padding(message, digest_length, byteorder='big'):
    """Get MD-compliant padding for a given message: 1+0*N+len(message), where
    length is interpreted as a 64-bit number. Length of digest blocks is specified
    in bits (e.g., 512 for SHA-1)"""
    ml = len(message)*8 # original length, in bits
    pad = bytes([128])
    m_mod = (ml+1) % digest_length
    pad_len = (digest_length-64)-m_mod
    pad_len += digest_length if pad_len<0 else 0
    pad += bytes(pad_len//8)
    pad += ml.to_bytes(8, byteorder)
    return pad

def MD4(message, init=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
        do_pad=True):
    h0, h1, h2, h3 = init

    if do_pad:
        m = message+MD_padding(message, 512, byteorder='little')
    elif len(message)%64>0:
        raise ValueError('Message must be in 512-bit blocks to forgo padding')
    else:
        m = message

    m_chunks = to_chunks(m, 64)
    for chunk in m_chunks:
        words = _MD4_chunk_to_words(chunk)

        buff = [h0, h1, h2, h3]
        buff = _MD4_round_1(words, buff)
        buff = _MD4_round_2(words, buff)
        buff = _MD4_round_3(words, buff)

        h0 = (h0+buff[0]) % 2**32
        h1 = (h1+buff[1]) % 2**32
        h2 = (h2+buff[2]) % 2**32
        h3 = (h3+buff[3]) % 2**32

    digest = [x.to_bytes(4, 'little') for x in [h0, h1, h2, h3]]
    return b''.join(digest)

def _MD4_chunk_to_words(chunk):
    """Break 512-bit chunk into 16 32-bit little-endian words,"""
    words = [int.from_bytes(x, 'little') for x in to_chunks(chunk, 4)]
    return words

def _MD4_round_1(words, buff):
    def f(x, y, z):
        return (x & y) | (bit_not(x, 32) & z)

    def r1(a, b, c, d, w, s):
        x = (a+f(b, c, d)+w) % 2**32
        return rot_left(x, s, 32)

    s_vals = [3, 7, 11, 19]
    for idx, (w, s) in enumerate(zip(words, cycle(s_vals))):
        adx, bdx, cdx, ddx = -idx%4, -(idx-1)%4, -(idx-2)%4, -(idx-3)%4
        buff[adx] = r1(buff[adx], buff[bdx], buff[cdx], buff[ddx], w, s)
    return buff

def _MD4_round_2(words, buff):
    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def r2(a, b, c, d, w, s):
        x = (a+g(b, c, d)+w+0x5a827999) % 2**32
        return rot_left(x, s, 32)

    s_vals = [3, 5, 9, 13]
    for idx, (_, s) in enumerate(zip(words, cycle(s_vals))):
        w = words[4*(idx%4)+idx//4]
        adx, bdx, cdx, ddx = -idx%4, -(idx-1)%4, -(idx-2)%4, -(idx-3)%4
        buff[adx] = r2(buff[adx], buff[bdx], buff[cdx], buff[ddx], w, s)
    return buff

def _MD4_round_3(words, buff):
    def h(x, y, z):
        return x^y^z

    def r3(a, b, c, d, w, s):
        x = (a+h(b, c, d)+w+0x6ed9eba1) % 2**32
        return rot_left(x, s, 32)

    w_vals = [0, 2, 1, 3]
    s_vals = [3, 9, 11, 15]
    for idx, (_, s) in enumerate(zip(words, cycle(s_vals))):
        w = words[4*w_vals[idx%4]+w_vals[idx//4]]
        adx, bdx, cdx, ddx = -idx%4, -(idx-1)%4, -(idx-2)%4, -(idx-3)%4
        buff[adx] = r3(buff[adx], buff[bdx], buff[cdx], buff[ddx], w, s)
    return buff
