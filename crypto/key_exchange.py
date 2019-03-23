from secrets import randbelow

from crypto.utils import int_to_bytes

"""Public-private key exchange (e.g., Diffie-Hellman, RSA)"""

DH_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
DH_G = 2

def gen_DH_keys():
    """Return a tuple which are public-private keys for Diffie-Hellman, as
    bignums"""
    private = randbelow(2**256) % DH_P
    public = modexp(DH_G, private, DH_P)
    return private, public

def gen_DH_secret(private, public):
    """Return a Diffie-Hellman secret key given a private and public key,
    as a byte-like object."""
    return int_to_bytes(modexp(public, private, DH_P))

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
