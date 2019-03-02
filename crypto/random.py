from datetime import datetime

from .utils import mask_N

"""Pseudo-random number generation (e.g., Mersenne Twister"""

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
            next_val &= mask_N(32) # wrap to 32 bits
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
