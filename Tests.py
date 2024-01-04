import unittest
from HelperFunctions import *
from Rabin import *

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

    # def test_decrypt_ecb(self):
    #     ciphertext_blocks = [100, 200, 300]
    #     result = decrypt_ecb(ciphertext_blocks, self.p, self.q)
    #     self.assertIsInstance(result, str)
    #     self.print_test_result("test_decrypt_ecb", isinstance(result, str))

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

    # def test_decrypt_cbc(self):
    #     ciphertext_blocks = [100, 200, 300]
    #     iv_int = 20
    #     result = decrypt_cbc(ciphertext_blocks, self.p, self.q, iv_int)
    #     self.assertIsInstance(result, str)
    #     self.print_test_result("test_decrypt_cbc", isinstance(result, str))

    def test_validate_plaintext(self):
        plaintext = "Hello"
        self.assertIsNone(validate_plaintext(plaintext))
        with self.assertRaises(ValueError):
            validate_plaintext("")
        self.print_test_result("test_validate_plaintext", True)

if __name__ == "__main__":
    unittest.main()