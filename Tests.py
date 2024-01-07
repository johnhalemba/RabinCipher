import unittest
from HelperFunctions import *
from Rabin import *

class TestRabinCipher(unittest.TestCase):

    def setUp(self):
        self.p = generate_large_prime(32)
        self.q = generate_large_prime(32)
        while self.q == self.p:
            self.q = generate_large_prime(32)
        self.block_size = 6
        self.iv = 2

    def debug_info(self, test_name, plaintext, ciphertext, decrypted_text, test_result):
        print(f"Test: {test_name}")
        print(f"Plaintext: {plaintext}")
        print(f"Ciphertext (encrypted text): {ciphertext}")
        print(f"Decrypted Text: {decrypted_text}")
        print(f"Test Result: {'Passed' if test_result else 'Failed'}\n")


    def test_string_to_int_and_back(self):
        original_str = "Hello, World!"
        int_representation = string_to_int(original_str)
        self.assertIsInstance(int_representation, int)
        converted_back_str = int_to_string(int_representation)
        self.assertEqual(original_str, converted_back_str)

    def test_is_prime(self):
        self.assertTrue(is_prime(5))
        self.assertFalse(is_prime(4))

    def test_generate_large_prime(self):
        prime = generate_large_prime(32)
        self.assertTrue(is_prime(prime))

    def test_extended_gcd(self):
        gcd, x, y = extended_gcd(35, 15)
        self.assertEqual(gcd, 5)
        self.assertEqual(35*x + 15*y, gcd)

    def test_modular_inverse(self):
        a, m = 3, 11
        inv = modular_inverse(a, m)
        self.assertEqual((a * inv) % m, 1)

    def test_rabin_encrypt_decrypt_block(self):
        m = string_to_int("Test")
        c = rabin_encrypt_block(m, self.p, self.q)
        self.assertIsInstance(c, int)
        possibilities = rabin_decrypt_block(c, self.p, self.q)
        self.assertIn(m, possibilities)

    def test_encrypt_decrypt_ecb(self):
        plaintext = "Test ECB encryption and decryption"
        ciphertext_blocks = encrypt_ecb(plaintext, self.p, self.q, self.block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, self.p, self.q)
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_decrypt_cbc(self):
        plaintext = "Test CBC encryption and decryption"
        ciphertext_blocks = encrypt_cbc(plaintext, self.p, self.q, self.block_size, self.iv)
        decrypted_text = decrypt_cbc(ciphertext_blocks, self.p, self.q, self.iv)
        self.assertEqual(plaintext, decrypted_text)

    def test_xor_ints(self):
        self.assertEqual(xor_ints(10, 5), 15)

    def test_pkcs7_padding(self):
        data = b"Hello"
        padded = pkcs7_pad(data, 8)
        self.assertEqual(len(padded), 8)
        unpadded = pkcs7_unpad(padded)
        self.assertEqual(data, unpadded)

    def test_encrypt_decrypt_ecb_special_characters(self):
        plaintext = "!@#$%^&*()_+~`|}{[]:;'<>,.?/"
        ciphertext_blocks = encrypt_ecb(plaintext, self.p, self.q, self.block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, self.p, self.q)
        self.assertEqual(plaintext, decrypted_text)
        print(f"ECB Special Characters Test:\nPlaintext: {plaintext}\nCiphertext: {ciphertext_blocks}\nDecrypted: {decrypted_text}")

    def test_encrypt_decrypt_cbc_special_characters(self):
        plaintext = "!@#$%^&*()_+~`|}{[]:;'<>,.?/"
        ciphertext_blocks = encrypt_cbc(plaintext, self.p, self.q, self.block_size, self.iv)
        decrypted_text = decrypt_cbc(ciphertext_blocks, self.p, self.q, self.iv)
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_decrypt_ecb_long_text(self):
        plaintext = "This is a longer text to test the ECB mode of Rabin cipher. It includes multiple sentences and different types of characters."
        ciphertext_blocks = encrypt_ecb(plaintext, self.p, self.q, self.block_size)
        decrypted_text = decrypt_ecb(ciphertext_blocks, self.p, self.q)
        self.assertEqual(plaintext, decrypted_text)

    def test_encrypt_decrypt_cbc_long_text(self):
        plaintext = "This is a longer text to test the CBC mode of Rabin cipher. It includes multiple sentences and different types of characters."
        ciphertext_blocks = encrypt_cbc(plaintext, self.p, self.q, self.block_size, self.iv)
        decrypted_text = decrypt_cbc(ciphertext_blocks, self.p, self.q, self.iv)
        self.assertEqual(plaintext, decrypted_text)

if __name__ == "__main__":
    unittest.main()
