from HelperFunctions import *


def rabin_encrypt_block(m: str, p: int, q: int) -> int:
    """
    Encrypts a block of plaintext using the Rabin cipher.

    Args:
        m (int): The plaintext block to be encrypted.
        p (int): The first prime number used in the encryption.
        q (int): The second prime number used in the encryption.

    Returns:
        int: The encrypted ciphertext block.

    """
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p and q must be prime numbers")
    n = p * q
    return pow(m, 2, n)

def rabin_decrypt_block(c, p, q):
    """
    Decrypts a Rabin cipher block using the given prime numbers p and q.

    Args:
        c (int): The ciphertext block to decrypt.
        p (int): The first prime number.
        q (int): The second prime number.

    Returns:
        tuple: A tuple containing four possible plaintext values (r, s, t, u).
    """
    if not all(isinstance(x, int) for x in [c, p, q]):
        raise TypeError("c, p and q must be integers.")
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    yp = modular_inverse(p, q)
    yq = modular_inverse(q, p)

    r = (mp * q * yq + mq * p * yp) % n
    s = n - r
    t = (mp * q * yq - mq * p * yp) % n
    u = n - t

    return r, s, t, u

def encrypt_ecb(plaintext: str, p: int, q: int, block_size):
    """
    Encrypts the given plaintext using the Rabin cipher in ECB mode.

    Args:
        plaintext (str): The plaintext to be encrypted.
        p (int): The first prime number used in the Rabin encryption algorithm.
        q (int): The second prime number used in the Rabin encryption algorithm.
        block_size (int): The size of each block in the plaintext.

    Returns:
        list: A list of encrypted blocks.

    """
    if not plaintext:
        raise Exception("String cannot be empty")
    plaintext = pkcs7_pad(plaintext.encode(), block_size)  # Pad and then encode the plaintext
    ciphertext_blocks = []
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        block_int = string_to_int(block)
        encrypted_block = rabin_encrypt_block(block_int, p, q)
        ciphertext_blocks.append(encrypted_block)
    return ciphertext_blocks

def decrypt_ecb(ciphertext_blocks, p, q):
    """
    Decrypts a list of ciphertext blocks using the Rabin cipher in ECB mode.

    Args:
        ciphertext_blocks (list): List of ciphertext blocks to be decrypted.
        p (int): First prime factor of the modulus used in the Rabin cipher.
        q (int): Second prime factor of the modulus used in the Rabin cipher.

    Returns:
        str: The decrypted plaintext.

    """
    if not ciphertext_blocks:
        raise Exception("Ciphertext blocks cannot be empty.")
    decrypted_text = ""
    for block in ciphertext_blocks:
        decrypted_possibilites = rabin_decrypt_block(block, p, q)
        valid_decryption_found = False

        for possiblity in decrypted_possibilites:
            try:
                decrypted_block = int_to_string(possiblity)
                decrypted_text += decrypted_block
                valid_decryption_found = True
                break
            except UnicodeDecodeError:
                continue
            except ValueError:
                continue
        
        if not valid_decryption_found:
            decrypted_text += "[Undecodable Block]"
    
    return pkcs7_unpad(decrypted_text.encode()).decode()

def encrypt_cbc(plaintext: str, p, q, block_size, iv_int):
    """
    Encrypts the given plaintext using the Rabin cipher in CBC mode.

    Args:
        plaintext (str): The plaintext to be encrypted.
        p (int): The first prime number used in the Rabin encryption.
        q (int): The second prime number used in the Rabin encryption.
        block_size (int): The size of each block in bytes.
        iv_int (int): The initialization vector (IV) as an integer.

    Returns:
        list: The list of encrypted ciphertext blocks.
    """
    if not plaintext:
        raise Exception("Text cannot be empty.")
    plaintext = pkcs7_pad(plaintext.encode(), block_size)  # Pad and then encode the plaintext
    ciphertext_blocks = []
    previous_block = iv_int

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        block_int = string_to_int(block)
        block_int = xor_ints(block_int, previous_block)  # XOR with the previous block
        encrypted_block = rabin_encrypt_block(block_int, p, q)
        ciphertext_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return ciphertext_blocks

def decrypt_cbc(ciphertext_blocks, p, q, iv_int):
    """
    Decrypts a list of ciphertext blocks using the Rabin cipher in CBC mode.

    Args:
        ciphertext_blocks (list): List of ciphertext blocks to be decrypted.
        p (int): The first prime factor of the modulus used in the Rabin cipher.
        q (int): The second prime factor of the modulus used in the Rabin cipher.
        iv_int (int): The initialization vector (IV) used in CBC mode.

    Returns:
        str: The decrypted plaintext.

    Raises:
        None.
    """
    if not ciphertext_blocks:
        raise Exception("Cipher blocks cannot be empty.")
    decrypted_text = ""
    previous_block = iv_int

    for block in ciphertext_blocks:
        decrypted_possibilities = rabin_decrypt_block(block, p, q)
        decrypted_text_piece = ""

        for possibility in decrypted_possibilities:
            try:
                decrypted_block = xor_ints(possibility, previous_block)  # XOR with the previous block
                decrypted_text_piece = int_to_string(decrypted_block)
                decrypted_text += decrypted_text_piece
                previous_block = block  # Update previous block to current ciphertext block
                break
            except UnicodeDecodeError:
                continue
            except ValueError:
                continue

        if decrypted_text_piece == "":
            decrypted_text += "[Undecodable Block]"
    return pkcs7_unpad(decrypted_text.encode()).decode()
