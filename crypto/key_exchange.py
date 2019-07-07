from hashlib import sha1
from secrets import randbelow

from Crypto.Util.number import getStrongPrime
import numpy as np

from crypto.utils import int_to_bytes

"""Public-private key exchange (e.g., Diffie-Hellman, RSA)"""

"""Default cyclic group parameters for Diffie-Hellman"""
DH_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
DH_G = 2

def gen_DH_keys(p=DH_P, g=DH_G):
    """Generate Diffie-Hellman key pair (public, private), given a cyclic
    group defined by modulus p and generator g
    """
    private = randbelow(2**256) % p
    public = pow(g, private, p)
    return public, private

def gen_DH_secret(public, private, p=DH_P):
    """Return a Diffie-Hellman secret key, as a bytes-like"""
    return int_to_bytes(pow(public, private, p))

def modinv(a, m):
    """Compute modular multiplicative inverse of a with respect to m.
    That is, find a such that ax = 1 (mod m)
    """
    bezout, gcd = egcd(a, m)
    if gcd != 1:
        return ValueError('Modular inverse does not exist')
    return bezout[0] % m

def egcd(a, b):
    """Given two integers a and b, compute the Bézout coefficients (s, t)
    and the gcd, using the Extended Euclidean Algorithm
    """
    s, old_s, t, old_t, r, old_r = 0, 1, 1, 0, b, a

    while r > 0:
        q = old_r // r
        old_r, r = r, old_r-q*r
        old_s, s = s, old_s-q*s
        old_t, t = t, old_t-q*t

    bezout, gcd = (old_s, old_t), old_r
    return bezout, gcd

def gen_RSA_keys(N=1024, e=3):
    """Generate public and private keys for N-bit RSA, using the public
    exponent e. Each key is returned as a tuple (e/d, n), where e/d is the
    public/private exponent, and n is the modulus.
    """
    p, q = getStrongPrime(N//2, e=e), getStrongPrime(N//2, e=e)
    n = p*q
    totient = (p-1)*(q-1) # Euler's totient vs. Carmichael's..easier
    d = modinv(e, totient)
    return (e, n), (d, n)

def cipher_RSA(data, key):
    """Process data using the given RSA key (exponent, modulus)

    Input data can be an int or bytes-like (interpreted as big-endian).
    We'll return either an int or bytes, respectively
    """
    byte_input = False
    if isinstance(data, bytes) or isinstance(data, bytearray):
        byte_input =True
        data = int.from_bytes(data, 'big')
    cipher =  pow(data, key[0], key[1])
    if byte_input:
        cipher = int_to_bytes(cipher)
    return cipher

def RSA_broadcast_attack(public_keys, ciphertexts):
    """Given a set of RSA public keys and corresponding ciphertexts, using
    the same exponents and plaintext but different moduli, use Håstad's
    broadcast attack decipher the plain-text.

    For this attack to work, the number of ciphertexts must be greater-than
    or equal to the exponent
    """
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
        residue += c*m*modinv(m, n)
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

"""Hard-coded DSA parameters, moduli p/q and generator g"""
DSA_P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
DSA_Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
DSA_G = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def gen_DSA_keys(p=DSA_P, q=DSA_Q, g=DSA_G):
    """Generate DSA public/private keys, using moduli p/q and generator g"""
    private = randbelow(q)
    public = pow(g, private, p)
    return public, private

def sign_DSA(message_hash, private, p=DSA_P, q=DSA_Q, g=DSA_G):
    """Produce a DSA signature tuple for a given message hash (as int),
    given a private key, moduli p/q and generator g
    """
    k = randbelow(q)
    r = pow(g, k, p) % q

    k_inv = modinv(k, q)
    s = k_inv*(message_hash+private*r) % q
    return (r, s)

def verify_DSA(message_hash, signature, public, p=DSA_P, q=DSA_Q, g=DSA_G):
    """Return true if a given DSA signature and public key matches a message hash"""
    r, s = signature
    if not (0 < r < q) or not (0 < s < q):
        raise ValueError('Invalid signature values')

    s_inv = modinv(s, q)

    u1 = s_inv*message_hash % q
    u2 = s_inv*r % q

    mod1 = pow(g, u1, p)
    mod2 = pow(public, u2, p)
    v = (mod1*mod2 % p) % q

    return v==r

def recover_DSA_private(message_hash, signature, k, q=DSA_Q):
    """Given a message hash (as int) and DSA signature tuple, and the
    per-user random key 'k', recover the signer's private key
    """
    r, s = signature
    r_inv = modinv(r, q)
    return r_inv*((s*k)-message_hash) % q

