from Crypto.Cipher import AES

"""Block ciphers, including stream ciphers implemented using CTR mode"""

def detect_ECB(cipher, block_size=AES.block_size):
    """Detect whether an encrypted ciphertext used ECB, by looking for
    repeated code blocks."""
    num_blocks = len(cipher)//block_size
    blocks = [cipher[x*block_size:(x+1)*block_size] for x in range(num_blocks)]
    return len(blocks) != len(set(blocks))
