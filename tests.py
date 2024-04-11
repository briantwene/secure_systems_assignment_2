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

sys.path.insert(0, "./aes")
rijndael = ctypes.CDLL("./rijndael.so")


class TestAES(unittest.TestCase):

    def generate_data(self):
        # generate bytes
        self.buffer = random.randbytes(16)
        self.python_block = bytes2matrix(self.buffer)
        self.c_block = self.buffer

    def test_sub_bytes(self):
        try:
            for _ in range(3):
                self.generate_data()
                sub_bytes(self.python_block)
                rijndael.sub_bytes(self.c_block)
                flattend_python_block = matrix2bytes(self.python_block)
                self.assertEqual(self.c_block.rstrip(), flattend_python_block)
        except AssertionError:
            print("test_sub_bytes failed ❌")

    def test_shift_rows(self):
        try:
            for _ in range(3):
                self.generate_data()
                shift_rows(self.python_block)
                rijndael.shift_rows(self.c_block)
                flattend_python_block = matrix2bytes(self.python_block)
                self.assertEqual(self.c_block, flattend_python_block)
        except AssertionError:
            print("test_shift_rows failed ❌")

    def test_mix_columns(self):
        try:
            for _ in range(3):
                self.generate_data()
                mix_columns(self.python_block)
                rijndael.mix_columns(self.c_block)

                flattend_python_block = matrix2bytes(self.python_block)
                print(list(self.c_block), list(flattend_python_block))
                self.assertEqual(self.c_block, flattend_python_block)
        except AssertionError:
            print("test_mix_columns failed ❌")


if __name__ == "__main__":
    unittest.main()
