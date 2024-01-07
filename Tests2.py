import unittest
from Rabin import *

class TestRabinCipher(unittest.TestCase):
    def setUp(self):
        self.p = generate_large_prime(32)
        self.q = generate_large_prime(32)
        while self.q == self.p:
            self.q = generate_large_prime(32)
        self.block_size = 4  # Example block size

    def test_encrypt_decrypt(self):
        plaintext = "Hello, Rabin Cipher!"
        ciphertext_blocks = encrypt_ecb(plaintext, self.p, self.q, self.block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, self.p, self.q)
        self.assertEqual(plaintext, decrypted_text)

    def test_empty_string(self):
        plaintext = ""
        with self.assertRaises(Exception):
            encrypt_ecb(plaintext, self.p, self.q, self.block_size)

    def test_long_string(self):
        plaintext = "a" * 1000  # A very long string
        ciphertext_blocks = encrypt_ecb(plaintext, self.p, self.q, self.block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, self.p, self.q)
        self.assertEqual(plaintext, decrypted_text)

    def test_special_characters(self):
        plaintext = "!@#$%^&*()_+"
        ciphertext_blocks = encrypt_ecb(plaintext, self.p, self.q, self.block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, self.p, self.q)
        self.assertEqual(plaintext, decrypted_text)

    def test_invalid_block_size(self):
        plaintext = "Test"
        with self.assertRaises(SomeException):  # Replace SomeException with the expected exception type
            encrypt_ecb(plaintext, self.p, self.q, 0)  # Invalid block size

    def test_invalid_prime_numbers(self):
        plaintext = "Test"
        with self.assertRaises(SomeException):  # Replace SomeException with the expected exception type
            encrypt_ecb(plaintext, 1, 1, self.block_size)  # Invalid primes

if __name__ == '__main__':
    unittest.main()

