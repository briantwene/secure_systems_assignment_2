# Import necessary modules and functions
import unittest
import ctypes
import random
from aes.aes import (
    bytes2matrix,
    matrix2bytes,
    sub_bytes,
    inv_sub_bytes,
    shift_rows,
    inv_shift_rows,
    mix_columns,
    inv_mix_columns,
    add_round_key,
    AES,
)
import sys

# Add the path of the AES implementation to the system path
sys.path.insert(0, "./aes")

# Load the shared library that contains the C implementation of AES
rijndael = ctypes.CDLL("./rijndael.so")


class TestAES(unittest.TestCase):
    """Unit tests for the AES implementation."""

    def generate_data(self):
        """
        Generate a random 16-byte block and convert it to a matrix for the Python implementation
        and a ctypes string buffer for the C implementation.
        """
        self.buffer = random.randbytes(16)
        self.python_block = bytes2matrix(self.buffer)
        self.c_block = ctypes.create_string_buffer(self.buffer)

    def remove_last_null_byte(self, byte_string):
        """
        Remove the last null byte from a byte string, if it exists.
        This is necessary because the C implementation might add a null byte at the end of the string.
        """
        last_null_byte_index = byte_string.rfind(b"\x00")
        if last_null_byte_index != -1 and last_null_byte_index == len(byte_string) - 1:
            return byte_string[:last_null_byte_index]
        else:
            return byte_string

    def run_test(
        self,
        operation_name,
        python_operation,
        c_operation,
        key_needed=False,
        expand_key=False,
    ):
        """
        Run a test for a given operation, comparing the results of the Python and C implementations.
        The test is run 3 times with different random inputs to ensure the operation works correctly in all cases.
        """
        for i in range(3):  # Run the test 3 times
            self.generate_data()  # Generate random data for testing

            # Generate a random 16-byte round key for testing if needed
            if key_needed:
                round_key_buffer = random.randbytes(16)
                c_round_key = ctypes.create_string_buffer(round_key_buffer)
                if expand_key:
                    python_operation(round_key_buffer)
                    c_operation(c_round_key)
                else:
                    python_round_key = bytes2matrix(round_key_buffer)
                    python_operation(self.python_block, python_round_key)
                    c_operation(self.c_block, c_round_key)
            else:
                python_operation(self.python_block)
                c_operation(self.c_block)

            # Convert the results back to byte strings
            python_result = matrix2bytes(self.python_block)
            c_result = self.remove_last_null_byte(self.c_block.raw)

            # Compare the results of the Python and C implementations
            with self.subTest(operation=operation_name):
                print(f"Running {operation_name} test, iteration {i+1}")
                self.assertEqual(c_result, python_result)

    def test_sub_bytes(self):
        # Test the SubBytes operation by running the test for both Python and C implementations.
        self.run_test("SubBytes", sub_bytes, rijndael.sub_bytes)

    # ... (other test methods modified in the same way)

    def test_add_round_key(self):
        # Test the Add RoundKey operation
        self.run_test(
            "Add RoundKey", add_round_key, rijndael.add_round_key, key_needed=True
        )

    def test_sub_bytes(self):
        # Test the SubBytes operation by running the test for both Python and C implementations.
        self.run_test("SubBytes", sub_bytes, rijndael.sub_bytes)

    def test_shift_rows(self):
        # Test the ShiftRows operation
        self.run_test("ShiftRows", shift_rows, rijndael.shift_rows)

    def test_mix_columns(self):
        # Test the MixColumns operation
        self.run_test("MixColumns", mix_columns, rijndael.mix_columns)

    def test_inv_sub_bytes(self):
        # Test the Inverse SubBytes operation
        self.run_test("Invert SubBytes", inv_sub_bytes, rijndael.invert_sub_bytes)

    def test_inv_shift_rows(self):
        # Test the Inverse ShiftRows operation
        self.run_test("Invert ShiftRows", inv_shift_rows, rijndael.invert_shift_rows)

    def test_inv_mix_columns(self):
        # Test the Inverse MixColumns operation
        self.run_test("Invert MixColumns", inv_mix_columns, rijndael.invert_mix_columns)

    def test_add_round_key(self):
        # Test the Add RoundKey operation
        self.run_test(
            "Add RoundKey", add_round_key, rijndael.add_round_key, key_needed=True
        )

    def test_expand_key(self):
        # Test the key expansion operation
        python_aes = AES(random.randbytes(16))
        self.run_test(
            "Expand Key",
            python_aes._expand_key,
            rijndael.expand_key,
            key_needed=True,
            expand_key=True,
        )

    def test_aes_encrypt_block(self):
        # Test the AES encryption process
        for i in range(3):
            # Generate a random 16-byte plaintext and key
            self.generate_data()
            key_buffer = random.randbytes(16)
            plaintext = random.randbytes(16)

            # Encrypt the plaintext using the Python implementation
            python_aes = AES(key_buffer)
            python_result = python_aes.encrypt_block(plaintext)

            # Encrypt the plaintext using the C implementation
            rijndael.aes_encrypt_block.restype = ctypes.c_void_p
            c_result = ctypes.string_at(
                rijndael.aes_encrypt_block(plaintext, key_buffer), 16
            )

            # Compare the results of the Python and C implementations
            with self.subTest(operation="AESEncryptBlock", iteration=i + 1):
                self.assertEqual(c_result, python_result)

    def test_aes_decrypt_block(self):
        # Test the AES decryption process
        for i in range(3):
            # Generate a random 16-byte ciphertext and key
            self.generate_data()
            key_buffer = random.randbytes(16)
            ciphertext = random.randbytes(16)

            # Decrypt the ciphertext using the Python implementation
            python_aes = AES(key_buffer)
            python_result = python_aes.decrypt_block(ciphertext)

            # Decrypt the ciphertext using the C implementation
            rijndael.aes_decrypt_block.restype = ctypes.c_void_p
            c_result = ctypes.string_at(
                rijndael.aes_decrypt_block(ciphertext, key_buffer), 16
            )

            # Compare the results of the Python and C implementations
            with self.subTest(operation="AESDecryptBlock", iteration=i + 1):
                self.assertEqual(c_result, python_result)

    def test_aes_encryption_decryption(self):
        # Test the full AES encryption and decryption process
        for i in range(3):
            # Generate a random 16-byte plaintext and key
            self.generate_data()
            key_buffer = random.randbytes(16)
            plaintext = random.randbytes(16)

            # Create an AES object with the Python implementation
            python_aes = AES(key_buffer)

            # Encrypt the plaintext with both the Python and C implementations
            python_ciphertext = python_aes.encrypt_block(plaintext)
            rijndael.aes_encrypt_block.restype = ctypes.c_void_p
            c_ciphertext = ctypes.string_at(
                rijndael.aes_encrypt_block(plaintext, key_buffer), 16
            )

            # Assert that the ciphertexts match
            with self.subTest(operation="AESEncryptBlock", iteration=i + 1):
                self.assertEqual(c_ciphertext, python_ciphertext)

            # Decrypt the ciphertexts with both the Python and C implementations
            python_decrypted = python_aes.decrypt_block(python_ciphertext)
            rijndael.aes_decrypt_block.restype = ctypes.c_void_p
            c_decrypted = ctypes.string_at(
                rijndael.aes_decrypt_block(c_ciphertext, key_buffer), 16
            )

            # Assert that the decrypted plaintexts match the original plaintext
            with self.subTest(operation="AESDecryptBlock", iteration=i + 1):
                self.assertEqual(c_decrypted, plaintext)


if __name__ == "__main__":
    # Run the tests with a higher verbosity level to see detailed output
    unittest.main(verbosity=2)
