from secrets import randbelow

from Crypto.Util.number import getStrongPrime
import numpy as np

from crypto.utils import int_to_bytes

"""Public-private key exchange (e.g., Diffie-Hellman, RSA)"""

DH_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
DH_G = 2

def gen_DH_keys(p=DH_P, g=DH_G):
    """Return a tuple which are public-private keys for Diffie-Hellman, as
    bignums"""
    private = randbelow(2**256) % p
    public = modexp(g, private, p)
    return private, public

def gen_DH_secret(private, public, p=DH_P):
    """Return a Diffie-Hellman secret key given a private and public key,
    as a byte-like object."""
    return int_to_bytes(modexp(public, private, p))

def modexp(g, u, p):
    """Compute (g**u) mod p using fast and memory-efficient algorithm
    (no overflow), based on pseudo-code from Schneier's Applied Crypto"""
    s = 1
    while u != 0:
        if u & 1:
            s = (s*g) % p
        u >>= 1
        g = (g*g) %p
    return s

def invmod(a, m):
    """Compute modular multiplicative inverse of a with respect to m.
    That is, find a such that ax = 1 (mod m)"""
    bezout, gcd = egcd(a, m)
    if gcd != 1:
        return ValueError('Modular inverse does not exist')
    return bezout[0] % m

def egcd(a, b):
    """Compute the Bezout coefficients (returned as a tuple) and the
    gcd of two integers a and b, using the Extended Euclidean Algorithm"""
    s, old_s, t, old_t, r, old_r = 0, 1, 1, 0, b, a

    while r > 0:
        q = old_r // r
        old_r, r = r, old_r-q*r
        old_s, s = s, old_s-q*s
        old_t, t = t, old_t-q*t

    return (old_s, old_t), old_r

def gen_RSA_keys():
    """Generate public and private keys for the RSA cryptosystem. Each
    is returned as a tuple (e, n), where e is the public (private) exponent
    and n is the modulus"""
    e = 3 # public-key exponent fixed at smallest possible coprime value
    p, q = getStrongPrime(1024, e=e), getStrongPrime(1024, e=e)
    n = p*q
    totient = (p-1)*(q-1)
    d = invmod(e, totient)
    return (e, n), (d, n)

def cipher_RSA(data, key):
    return modexp(data, key[0], key[1])

def RSA_broadcast_attack(public_keys, ciphertexts):
    """Use Håstad's broadcast attack to break RSA using small public-key
    exponents (e.g., e = 3). List public_keys and ciphertexts are the
    public-key tuples for RSA and corresponding encrypted plaintexts,
    assuming that the ciphertexts all correspond to the same plaintext.
    For this attack to work, N >= e encryptions must be given"""
    e_vals = set([p[0] for p in public_keys])
    if len(e_vals) != 1:
        raise ValueError('Public-key exponent must match for all ciphers')

    e = public_keys[0][0]
    if len(public_keys) < e or len(ciphertexts) < e:
        raise ValueError('Broadcast attack requires at least e ciphertexts')

    n_vals = [p[1] for p in public_keys[:e]]
    N = np.product(n_vals)
    residue = 0
    for c, n in zip(ciphertexts[:e], n_vals):
        m = N // n
        residue += c*m*invmod(m, n)
    residue = residue % N
    return invpow(residue, e)

def invpow(x, n):
    """Find the n-th root of an integer x using binary search. This should
    work even if the integer is too large to convert to float (i.e., if
    pow(x, 1/n) fails"""

    """Find brackets [N, 2*N] which contain the root"""
    high = 1
    while high**n <= x:
        high *= 2
    low = high // 2

    while low < high:
        mid = (low + high) // 2
        mid_pow = mid**n
        if low < mid and mid_pow < x:
            low = mid
        elif high > mid and mid_pow > x:
            high = mid
        else:
            return mid
    return mid + 1
