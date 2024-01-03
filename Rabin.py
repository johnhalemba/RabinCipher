import random
import math
import unittest
import sys

def string_to_int(s):
    """
    Converts a string to an integer representation.

    Parameters:
    s (str): The string to be converted.

    Returns:
    int: The integer representation of the string.
    """
    return int.from_bytes(s.encode(), 'big')

def int_to_string(i):
    """
    Converts an integer to a string representation.

    Parameters:
    i (int): The integer to be converted.

    Returns:
    str: The string representation of the integer.
    """
    return i.to_bytes((i.bit_length() + 7) // 8, 'big').decode()

def is_prime(n):
    """
    Check if a number is prime.

    Args:
        n (int): The number to be checked.

    Returns:
        bool: True if the number is prime, False otherwise.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    sqrt_n = int(math.sqrt(n)) + 1
    for i in range(5, sqrt_n, 6):
        if n % i == 0 or n % (i + 2) == 0:
            return False
    return True

def generate_large_prime(key_size):
    """
    Generates a large prime number of the specified key size.

    Parameters:
    key_size (int): The size of the prime number to be generated.

    Returns:
    int: A large prime number.
    """
    while True:
        n = random.randrange(2**(key_size-1), 2**key_size)
        if n % 4 == 3 and is_prime(n):
            return n
        
def extended_gcd(a,b):
    """
    Calculates the extended greatest common divisor (gcd) of two integers.

    Parameters:
    a (int): The first integer.
    b (int): The second integer.

    Returns:
    tuple: A tuple containing the gcd and the coefficients x and y such that ax + by = gcd.
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modular_inverse(a, m):
    """
    Calculates the modular inverse of a number 'a' modulo 'm'.

    Parameters:
    a (int): The number for which the modular inverse is to be calculated.
    m (int): The modulus.

    Returns:
    int: The modular inverse of 'a' modulo 'm'.

    Raises:
    Exception: If the modular inverse does not exist.
    """
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return x % m

def rabin_encrypt_block(m, p, q):
    """
    Encrypts a block of plaintext using the Rabin cipher.

    Args:
        m (int): The plaintext block to be encrypted.
        p (int): The first prime number used in the encryption.
        q (int): The second prime number used in the encryption.

    Returns:
        int: The encrypted ciphertext block.

    """
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

def encrypt_ecb(plaintext, p, q, block_size):
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
        
        if not valid_decryption_found:
            decrypted_text += "[Undecodable Block]"
    
    return decrypted_text

def xor_ints(int1, int2):
    """ XOR two integers.

    Args:
        int1 (int): The first integer.
        int2 (int): The second integer.

    Returns:
        int: The result of XOR operation between int1 and int2.
    """
    return int1 ^ int2

def encrypt_cbc(plaintext, p, q, block_size, iv_int):
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

        if decrypted_text_piece == "":
            decrypted_text += "[Undecodable Block]"
    return decrypted_text

def validate_plaintext(plaintext):
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")

def read_plaintext_from_file(file_path, encoding='utf-8'):
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            plaintext = f.read()
    except FileNotFoundError as e:
        raise Exception("File not found: " + file_path)
    except Exception as e:
        raise Exception("Error reading file: " + file_path)

    return plaintext

def get_plaintext():
    while True:
        choice = input("Do you want to provide the plaintext string from the console? If no, you will have to provide filepath (y/n): ").lower()
        if choice == 'y':
            plaintext = input("Enter the plaintext string: ")
            try:
                validate_plaintext(plaintext) #checking if plaintext is empty -> it should
                return plaintext  # Return the entered plaintext
            except ValueError as e:
                print(f"Error: {e}")
        elif choice == 'n':
            file_path = input("Enter path to the plaintext file: ")
            try:
                plaintext = read_plaintext_from_file(file_path, encoding='utf-8')
                validate_plaintext(plaintext)
                return plaintext  # Return the plaintext read from the file
            except Exception as e:
                print(f"Error: {e}")
        else:
            print("Invalid choice. Please enter 'y' or 'n'.")

def main():
    p = generate_large_prime(32)
    q = generate_large_prime(32)
    while q == p:
        q = generate_large_prime(32)
    print(f"p = {p}")
    print(f"q = {q}")
    mode = input("Enter mode (EBC/CBC): ")
    block_size = int(input("Enter block size: "))  # Allow the user to input block size
    
    plaintext = get_plaintext()

    #block_size = 4

    if mode.upper() == "EBC":
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
    elif mode.upper() == "CBC":
        iv = 20
        ciphertext_blocks = encrypt_cbc(plaintext, p, q, block_size, iv)
        decrypted_text = decrypt_cbc(ciphertext_blocks, p, q, iv)
    else:
        print("Invalid mode")
        return
    
    print("Plaintext:", plaintext)
    print("Ciphertect Blocks: ", ciphertext_blocks)
    print("Decrypted Text: ", decrypted_text)

def setUp(self):
        self.p = generate_large_prime(32)
        self.q = generate_large_prime(32)
        self.block_size = 4  # Example block size, adjust as needed
        self.iv = 10  # Example IV for CBC mode
        
def test_cases():
    print("List of test cases ")
    print("Test 1: Empty string as plaintext input")
    print("Test 2: Short string 'abc'in ECB mode")
    print("Test 3: Short string 'abc' in CBC mode")
    print("Test 4: Long string 'this is a longer sentence to perform test4' in ECB mode")
    print("Test 5: Long string 'this is a longer sentence to perform test5' in CBC mode")
    print("Test 6: Plaintext consists of numbers: '12345'")
    print("Test 7: Plaintext consists of special characters: '!@#$%^&*+'")
    print("Test 8: Plaintext consists of extended ASCI : '!Mąę'")
    print("Test 9: Plaintext is single character 'a'")
    
    test_number = int(input("Enter the option number from 1 up to 10: ").lower())
    if test_number == 1:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "EBC"
        block_size = 4
        plaintext = ""
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 2:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "EBC"
        block_size = 4
        plaintext = "abc"
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 3:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "CBC"
        block_size = 4
        plaintext = "abc"
        iv = 20
        ciphertext_blocks = encrypt_cbc(plaintext, p, q, block_size, iv)
        decrypted_text = decrypt_cbc(ciphertext_blocks, p, q, iv)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 4:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "EBC"
        block_size = 4
        plaintext = "this is a longer sentence to perform test4"
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 5:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "CBC"
        block_size = 4
        plaintext = "this is a longer sentence to perform test5"
        iv = 20
        ciphertext_blocks = encrypt_cbc(plaintext, p, q, block_size, iv)
        decrypted_text = decrypt_cbc(ciphertext_blocks, p, q, iv)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 6:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "EBC"
        block_size = 4
        plaintext = "12345"
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 7:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "EBC"
        block_size = 4
        plaintext = "!@#$%^&*+"
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 8:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "EBC"
        block_size = 4
        plaintext = "!Mąę"
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    elif test_number == 9:
        p = generate_large_prime(32)
        q = generate_large_prime(32)
        while q == p:
            q = generate_large_prime(32)
        mode = "EBC"
        block_size = 4
        plaintext = "a"
        ciphertext_blocks = encrypt_ecb(plaintext, p, q, block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, p, q)
        print("Plaintext:", plaintext)
        print("Ciphertext Blocks:", ciphertext_blocks)
        print("Decrypted Text:", decrypted_text)
    else:
        print("Invalid test number. Please choose a test number between 1 and 10.")

def run_program():
    print("Dear user, you are using Rabin cipher program")
    print("How do you want to use the program? Choose the option you are interested in:")
    print("1. Encrypt and decrypt your own string from console or file")
    print("2. Check if the all functions are working correctly")
    print("3. List of Test cases which can be perfromed")

    choice = input("Enter the option number (1/2/3): ").lower()

    if choice == '1':
        main()
    elif choice == '2':
        unittest.main()
    elif choice == '3':
        test_cases()
    else:
        print("Invalid choice. Please enter '1', '2', or '3'.")

class TestRabinCipher(unittest.TestCase):

    def setUp(self):
        self.p = generate_large_prime(32)
        self.q = generate_large_prime(32)
        while self.q == self.p:
            self.q = generate_large_prime(32)
        self.block_size = 4

    def print_test_result(self, test_name, result):
        print(f"Test: {test_name} - {'Passed' if result else 'Failed'}")

    def test_string_to_int(self):
        s = "Hello"
        result = string_to_int(s)
        self.assertIsInstance(result, int)
        self.print_test_result("test_string_to_int", isinstance(result, int))

    def test_int_to_string(self):
        i = 12345
        result = int_to_string(i)
        self.assertIsInstance(result, str)
        self.print_test_result("test_int_to_string", isinstance(result, str))

    def test_is_prime(self):
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
        non_primes = [1, 4, 6, 8, 9, 10, 12, 14, 15, 20]

        for prime in primes:
            self.assertTrue(is_prime(prime))

        for non_prime in non_primes:
            self.assertFalse(is_prime(non_prime))

        self.print_test_result("test_is_prime", True)  # Assumes all sub-tests pass

    def test_generate_large_prime(self):
        key_size = 32
        prime = generate_large_prime(key_size)
        self.assertTrue(is_prime(prime))
        self.assertGreaterEqual(prime, 2**(key_size-1))
        self.assertLess(prime, 2**key_size)
        self.print_test_result("test_generate_large_prime", True)

    def test_extended_gcd(self):
        a, b = 35, 15
        result = extended_gcd(a, b)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 3)
        self.print_test_result("test_extended_gcd", isinstance(result, tuple) and len(result) == 3)

    def test_modular_inverse(self):
        a, m = 3, 11
        result = modular_inverse(a, m)
        self.assertIsInstance(result, int)
        self.print_test_result("test_modular_inverse", isinstance(result, int))

    def test_rabin_encrypt_block(self):
        m, p, q = 10, self.p, self.q
        result = rabin_encrypt_block(m, p, q)
        self.assertIsInstance(result, int)
        self.print_test_result("test_rabin_encrypt_block", isinstance(result, int))

    def test_rabin_decrypt_block(self):
        c, p, q = 100, self.p, self.q
        result = rabin_decrypt_block(c, p, q)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 4)
        self.print_test_result("test_rabin_decrypt_block", isinstance(result, tuple) and len(result) == 4)

    def test_encrypt_ecb(self):
        plaintext = "Hello"
        result = encrypt_ecb(plaintext, self.p, self.q, self.block_size)
        self.assertIsInstance(result, list)
        self.print_test_result("test_encrypt_ecb", isinstance(result, list))

    def test_decrypt_ecb(self):
        ciphertext_blocks = [100, 200, 300]
        result = decrypt_ecb(ciphertext_blocks, self.p, self.q)
        self.assertIsInstance(result, str)
        self.print_test_result("test_decrypt_ecb", isinstance(result, str))

    def test_xor_ints(self):
        int1, int2 = 10, 5
        result = xor_ints(int1, int2)
        self.assertIsInstance(result, int)
        self.print_test_result("test_xor_ints", isinstance(result, int))

    def test_encrypt_cbc(self):
        plaintext = "Hello"
        iv_int = 20
        result = encrypt_cbc(plaintext, self.p, self.q, self.block_size, iv_int)
        self.assertIsInstance(result, list)
        self.print_test_result("test_encrypt_cbc", isinstance(result, list))

    def test_decrypt_cbc(self):
        ciphertext_blocks = [100, 200, 300]
        iv_int = 20
        result = decrypt_cbc(ciphertext_blocks, self.p, self.q, iv_int)
        self.assertIsInstance(result, str)
        self.print_test_result("test_decrypt_cbc", isinstance(result, str))

    def test_validate_plaintext(self):
        plaintext = "Hello"
        self.assertIsNone(validate_plaintext(plaintext))
        with self.assertRaises(ValueError):
            validate_plaintext("")
        self.print_test_result("test_validate_plaintext", True)

if __name__ == "__main__":
    # main()
    """unittest.main()"""
    run_program()

    