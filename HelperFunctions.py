from math import sqrt
from random import randrange

def string_to_int(s: str) -> int:
    """
    Converts a string to an integer representation.

    Parameters:
    s (str): The string to be converted.

    Returns:
    int: The integer representation of the string.
    """
    if not isinstance(s, (str, bytes)):
        raise TypeError("Input must be a string or bytes.")
    if isinstance(s, str):
        s = s.encode()
    return int.from_bytes(s, 'big')
def int_to_string(i: int) -> str:
    """
    Converts an integer to a string representation.

    Parameters:
    i (int): The integer to be converted.

    Returns:
    str: The string representation of the integer.
    """
    try:
        return i.to_bytes((i.bit_length() + 7) // 8, 'big').decode()
    except ValueError:
        raise ValueError("Invalid integer for conversion.")
def is_prime(n : int) -> bool:
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
    sqrt_n = int(sqrt(n)) + 1
    for i in range(5, sqrt_n, 6):
        if n % i == 0 or n % (i + 2) == 0:
            return False
    return True

def generate_large_prime(key_size: int) -> int:
    """
    Generates a large prime number of the specified key size.

    Parameters:
    key_size (int): The size of the prime number to be generated.

    Returns:
    int: A large prime number.
    """
    while True:
        n = randrange(2**(key_size-1), 2**key_size)
        if n % 4 == 3 and is_prime(n):
            return n
        
def extended_gcd(a: int,b: int) -> tuple[int, int, int]:
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

def modular_inverse(a: int, m: int) -> int:
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
    
def xor_ints(int1: int, int2: int) -> int:
    """ XOR two integers.

    Args:
        int1 (int): The first integer.
        int2 (int): The second integer.

    Returns:
        int: The result of XOR operation between int1 and int2.
    """
    return int1 ^ int2

def validate_plaintext(plaintext: str) -> None:
    """
    Validates the plaintext input.

    Args:
        plaintext (str): The plaintext to be validated.

    Raises:
        ValueError: If the plaintext is empty.

    """
    if not plaintext:
        raise ValueError("Plaintext cannot be empty.")

def read_plaintext_from_file(file_path: str, encoding: str='utf-8') -> str:
    """
    Read plaintext from a file.

    Args:
        file_path (str): The path to the file.
        encoding (str, optional): The encoding of the file. Defaults to 'utf-8'.

    Returns:
        str: The plaintext read from the file.

    Raises:
        Exception: If the file is not found or there is an error reading the file.
    """
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            plaintext = f.read()
    except FileNotFoundError as e:
        raise Exception("File not found: " + file_path)
    except Exception as e:
        raise Exception("Error reading file: " + file_path)

    return plaintext

def get_plaintext() -> str:
    """
    Prompts the user to provide the plaintext string either from the console or from a file.

    Returns:
        str: The plaintext string entered by the user or read from a file.

    Raises:
        ValueError: If the entered plaintext string is empty.
        Exception: If there is an error reading the plaintext from the file.
    """
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

def pkcs7_pad(data: bytes, block_size: int):
    """
    Pads the given data using PKCS7 padding scheme.

    Args:
        data (bytes): The data to be padded.
        block_size (int): The block size in bytes.

    Returns:
        bytes: The padded data.
    """
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    """
    Removes PKCS7 padding from the given data.

    Args:
        data (bytes): The data to remove padding from.

    Returns:
        bytes: The data with padding removed.

    Raises:
        ValueError: If the padding is invalid.
    """
    padding_len = data[-1]
    if padding_len > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_len]
