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

    def generate_data(self):
        # Generate a random 16-byte block and convert it to a matrix for the Python implementation
        # and a ctypes string buffer for the C implementation
        self.buffer = random.randbytes(16)
        self.python_block = bytes2matrix(self.buffer)
        self.c_block = ctypes.create_string_buffer(self.buffer)

    def remove_last_null_byte(self, byte_string):
        # Remove the last null byte from a byte string, if it exists
        last_null_byte_index = byte_string.rfind(b"\x00")
        if last_null_byte_index != -1 and last_null_byte_index == len(byte_string) - 1:
            return byte_string[:last_null_byte_index]
        else:
            return byte_string

    def run_test(self, python_operation, c_operation, operation_name):
        # Run a test for a given operation, comparing the results of the Python and C implementations
        for i in range(3):
            self.generate_data()

            python_operation(self.python_block)
            c_operation(self.c_block)

            python_result = matrix2bytes(self.python_block)
            c_result = self.remove_last_null_byte(self.c_block.raw)

            # Use a subTest to provide more detailed output in case of a test failure
            with self.subTest(operation=operation_name):
                print(f"Running {operation_name} test, iteration {i+1}")
                self.assertEqual(c_result, python_result)

    def run_test_with_key(self, python_operation, c_operation, operation_name):
        # Run a test for a given operation that requires a round key,
        # comparing the results of the Python and C implementations
        for i in range(3):
            self.generate_data()

            # Generate a random 16-byte round key and convert it to a matrix for the Python implementation
            # and a ctypes string buffer for the C implementation
            round_key_buffer = random.randbytes(16)
            python_round_key = bytes2matrix(round_key_buffer)
            c_round_key = ctypes.create_string_buffer(round_key_buffer)

            python_operation(self.python_block, python_round_key)
            c_operation(self.c_block, c_round_key)

            python_result = matrix2bytes(self.python_block)
            c_result = self.remove_last_null_byte(self.c_block.raw)

            # Use a subTest to provide more detailed output in case of a test failure
            with self.subTest(operation=operation_name):
                print(f"Running {operation_name} test, iteration {i+1}")
                self.assertEqual(c_result, python_result)

    def run_test_expand_key(self, python_operation, c_operation):
        # Run a test for the expand_key operation,
        # comparing the results of the Python and C implementations
        for i in range(3):
            self.generate_data()

            # Generate a random 16-byte round key and convert it to a matrix for the Python implementation
            # and a ctypes string buffer for the C implementation
            round_key_buffer = random.randbytes(16)
            python_round_key = round_key_buffer
            c_round_key = ctypes.create_string_buffer(round_key_buffer)
            key_size = ctypes.c_int(len(round_key_buffer))

            python_operation(python_round_key)
            c_operation(c_round_key, key_size)

            python_result = matrix2bytes(self.python_block)
            c_result = self.remove_last_null_byte(self.c_block.raw)

            # Use a subTest to provide more detailed output in case of a test failure
            with self.subTest(operation="ExpandKey"):
                print(f"Running ExpandKey test, iteration {i+1}")
                self.assertEqual(c_result, python_result)

    def test_sub_bytes(self):
        # Test the SubBytes operation
        self.run_test(sub_bytes, rijndael.sub_bytes, "SubBytes")

    def test_shift_rows(self):
        # Test the ShiftRows operation
        self.run_test(shift_rows, rijndael.shift_rows, "ShiftRows")

    def test_mix_columns(self):
        # Test the MixColumns operation
        self.run_test(mix_columns, rijndael.mix_columns, "MixColumn")

    def test_inv_sub_bytes(self):
        # Test the Inverse SubBytes operation
        self.run_test(inv_sub_bytes, rijndael.invert_sub_bytes, "Invert SubBytes")

    def test_inv_shift_rows(self):
        self.run_test(inv_shift_rows, rijndael.invert_shift_rows, "Invert ShiftRows")

    def test_inv_mix_columns(self):
        self.run_test(inv_mix_columns, rijndael.invert_mix_columns, "Invert MixColumns")

    def test_add_round_key(self):
        self.run_test_with_key(add_round_key, rijndael.add_round_key, "Add RoundKey")

    def test_expand_key(self):
        python_aes = AES(random.randbytes(16))
        self.run_test_expand_key(python_aes._expand_key, rijndael.expand_key)

    def test_aes_encrypt_block(self):
        # Test the AES encryption process
        for i in range(3):
            # Generate a random 16-byte plaintext and key
            self.generate_data()
            key_buffer = random.randbytes(16)
            plaintext = random.randbytes(16)

            python_aes = AES(key_buffer)
            python_result = python_aes.encrypt_block(plaintext)

            rijndael.aes_encrypt_block.restype = ctypes.c_void_p
            c_result = ctypes.string_at(
                rijndael.aes_encrypt_block(plaintext, key_buffer), 16
            )

            with self.subTest(operation="AESEncryptBlock", iteration=i + 1):
                self.assertEqual(c_result, python_result)


if __name__ == "__main__":
    # Run the tests with a higher verbosity level to see detailed output
    unittest.main(verbosity=2)
