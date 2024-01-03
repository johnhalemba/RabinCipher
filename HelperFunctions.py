from math import sqrt
from random import randrange

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
    sqrt_n = int(sqrt(n)) + 1
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
        n = randrange(2**(key_size-1), 2**key_size)
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
    
def xor_ints(int1, int2):
    """ XOR two integers.

    Args:
        int1 (int): The first integer.
        int2 (int): The second integer.

    Returns:
        int: The result of XOR operation between int1 and int2.
    """
    return int1 ^ int2

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