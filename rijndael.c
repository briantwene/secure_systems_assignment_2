/*
 * Name: Brian Twene
 * Student Number: C19344543
 *
 * This code implements the 128-bit version of the Rijndael cipher, also known
 * as Advanced Encryption Standard (AES). It includes functions for key
 * expansion, encryption, and decryption. The code uses a block size of 16 bytes
 * and a key size of 16 bytes (128 bits).
 */

#include "rijndael.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 16
#define EXPANDED_KEY_SIZE 176
#define RCON_SIZE 11

static const unsigned char s_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16};

static const unsigned char inv_s_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
    0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87,
    0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32,
    0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49,
    0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
    0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05,
    0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
    0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41,
    0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
    0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89,
    0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B,
    0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
    0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0C, 0x7D};

unsigned char r_con[256] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97,
    0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    // The rest of the array should be filled with 0s.
};

unsigned char xtime(unsigned char a) {
  return ((a << 1) ^ ((a & 0x80) ? 0x1B : 0)) & 0xFF;
}
/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
  // here we  are mapping each byte in the block to a value on the AES s_box
  // interesting thing is that C can interpret hex values as an index and even
  // binary
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      unsigned char byte = BLOCK_ACCESS(block, row, col);
      BLOCK_ACCESS(block, row, col) = s_box[byte];
    }
  }

  // no need to return anything as this is the pointer to the block
}

void shift_rows(unsigned char *block) {
  // blocks are in column-major order

  // 1 5 9  13
  // 2 6 10 14
  // 3 7 11 15
  // 4 8 12 16
  unsigned char temp[BLOCK_SIZE];

  // The first row isn't shifted.
  for (int i = 0; i < 4; i++) {
    BLOCK_ACCESS(temp, i, 0) = BLOCK_ACCESS(block, i, 0);
  }

  // The second row is shifted one position to the left.
  BLOCK_ACCESS(temp, 0, 1) = BLOCK_ACCESS(block, 1, 1);
  BLOCK_ACCESS(temp, 1, 1) = BLOCK_ACCESS(block, 2, 1);
  BLOCK_ACCESS(temp, 2, 1) = BLOCK_ACCESS(block, 3, 1);
  BLOCK_ACCESS(temp, 3, 1) = BLOCK_ACCESS(block, 0, 1);

  // The third row is shifted two positions to the left.
  BLOCK_ACCESS(temp, 0, 2) = BLOCK_ACCESS(block, 2, 2);
  BLOCK_ACCESS(temp, 1, 2) = BLOCK_ACCESS(block, 3, 2);
  BLOCK_ACCESS(temp, 2, 2) = BLOCK_ACCESS(block, 0, 2);
  BLOCK_ACCESS(temp, 3, 2) = BLOCK_ACCESS(block, 1, 2);

  // The fourth row is shifted three positions to the left.
  BLOCK_ACCESS(temp, 0, 3) = BLOCK_ACCESS(block, 3, 3);
  BLOCK_ACCESS(temp, 1, 3) = BLOCK_ACCESS(block, 0, 3);
  BLOCK_ACCESS(temp, 2, 3) = BLOCK_ACCESS(block, 1, 3);
  BLOCK_ACCESS(temp, 3, 3) = BLOCK_ACCESS(block, 2, 3);

  // Apply the changes to the block
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = temp[i];
  }
}

void mix_columns(unsigned char *block) {
  // implemented based off python implementation
  // uses a complex multiplication galoais, its not like simple multiplication
  // Temporary array to hold the current column.
  unsigned char tmp[4], t;

  // Loop over each column.
  for (int i = 0; i < 4; ++i) {
    // Copy the current column to the temporary array.
    for (int j = 0; j < 4; ++j) {
      tmp[j] = BLOCK_ACCESS(block, i, j);
    }

    // XOR all bytes in the column together.
    t = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];

    // Loop over each byte in the column.
    for (int j = 0; j < 4; ++j) {
      // Mix the column and apply it to the block.
      BLOCK_ACCESS(block, i, j) ^= t ^ xtime(tmp[j] ^ tmp[(j + 1) % 4]);
    }
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  // same as sub_bytes but use an inverse table lookup
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      BLOCK_ACCESS(block, i, j) = inv_s_box[BLOCK_ACCESS(block, i, j)];
    }
  }
}

void invert_shift_rows(unsigned char *block) {
  unsigned char temp[BLOCK_SIZE];

  // The first row isn't shifted.
  for (int i = 0; i < 4; i++) {
    BLOCK_ACCESS(temp, i, 0) = BLOCK_ACCESS(block, i, 0);
  }

  // The second row is shifted one position to the right.
  BLOCK_ACCESS(temp, 0, 1) = BLOCK_ACCESS(block, 3, 1);
  BLOCK_ACCESS(temp, 1, 1) = BLOCK_ACCESS(block, 0, 1);
  BLOCK_ACCESS(temp, 2, 1) = BLOCK_ACCESS(block, 1, 1);
  BLOCK_ACCESS(temp, 3, 1) = BLOCK_ACCESS(block, 2, 1);

  // The third row is shifted two positions to the right.
  BLOCK_ACCESS(temp, 0, 2) = BLOCK_ACCESS(block, 2, 2);
  BLOCK_ACCESS(temp, 1, 2) = BLOCK_ACCESS(block, 3, 2);
  BLOCK_ACCESS(temp, 2, 2) = BLOCK_ACCESS(block, 0, 2);
  BLOCK_ACCESS(temp, 3, 2) = BLOCK_ACCESS(block, 1, 2);

  // The fourth row is shifted three positions to the right.
  BLOCK_ACCESS(temp, 0, 3) = BLOCK_ACCESS(block, 1, 3);
  BLOCK_ACCESS(temp, 1, 3) = BLOCK_ACCESS(block, 2, 3);
  BLOCK_ACCESS(temp, 2, 3) = BLOCK_ACCESS(block, 3, 3);
  BLOCK_ACCESS(temp, 3, 3) = BLOCK_ACCESS(block, 0, 3);

  // Apply the changes to the block
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] = temp[i];
  }
}
// This function inverts the mix columns operation in AES
void invert_mix_columns(unsigned char *block) {
  unsigned char tmp[4];

  // Loop over each column.
  for (int i = 0; i < 4; ++i) {
    // Copy the current column to the temporary array.
    for (int j = 0; j < 4; ++j) {
      tmp[j] = BLOCK_ACCESS(block, i, j);
    }

    // Calculate u and v.
    unsigned char u = xtime(xtime(tmp[0] ^ tmp[2]));
    unsigned char v = xtime(xtime(tmp[1] ^ tmp[3]));

    // Apply u and v to the column.
    BLOCK_ACCESS(block, i, 0) ^= u;
    BLOCK_ACCESS(block, i, 1) ^= v;
    BLOCK_ACCESS(block, i, 2) ^= u;
    BLOCK_ACCESS(block, i, 3) ^= v;
  }

  // Mix the columns.
  mix_columns(block);
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      BLOCK_ACCESS(block, i, j) ^= BLOCK_ACCESS(round_key, i, j);
    }
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  int key_size = 16;  // Size of key in bytes
  int rounds = 10;    // Number of rounds for 128-bit AES
  int iteration_size = key_size / 4;
  int i, j;

  // Allocate memory for the expanded key
  char *expanded_key = malloc((rounds + 1) * key_size * sizeof(char));

  // Copy the initial cipher key into expanded_key
  for (i = 0; i < iteration_size; i++) {
    for (j = 0; j < 4; j++) {
      expanded_key[i * 4 + j] = cipher_key[i * 4 + j];
    }
  }

  // Key expansion
  char word[4], temp;
  for (; i < (rounds + 1) * 4; i++) {
    memcpy(word, &expanded_key[(i - 1) * 4], 4);

    if (i % iteration_size == 0) {
      // Circular shift
      temp = word[0];
      memmove(word, word + 1, 3);
      word[3] = temp;

      // S-box substitution
      for (j = 0; j < 4; j++) {
        word[j] = s_box[(uint8_t)word[j]];
      }

      // XOR with R-con
      word[0] ^= r_con[i / iteration_size];
    }

    // XOR with equivalent word from previous iteration
    for (j = 0; j < 4; j++) {
      expanded_key[i * 4 + j] =
          expanded_key[(i - iteration_size) * 4 + j] ^ word[j];
    }
  }

  return expanded_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // TODO: Implement me!

  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}
