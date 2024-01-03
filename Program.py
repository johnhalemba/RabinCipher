from Rabin import *

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

if __name__ == "__main__":
    # main()
    """unittest.main()"""
    run_program()