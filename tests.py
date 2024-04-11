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

    def test_sub_bytes(self):
        # Test the SubBytes operation
        self.run_test(sub_bytes, rijndael.sub_bytes, "sub_bytes")

    def test_shift_rows(self):
        # Test the ShiftRows operation
        self.run_test(shift_rows, rijndael.shift_rows, "shift_rows")

    def test_mix_columns(self):
        # Test the MixColumns operation
        self.run_test(mix_columns, rijndael.mix_columns, "mix_columns")


if __name__ == "__main__":
    # Run the tests with a higher verbosity level to see detailed output
    unittest.main(verbosity=2)
