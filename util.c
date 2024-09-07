/*
 * noclvag, Nostr OpenCL Vanity Address Generator.
 * Copyright (C) 2024 alex0jsan <nostr:npub1alex0jsan7wt5aq7exv9je9qlvdwm69sr7u6m8msjr77xv6yj60qkp8462>
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * noclvag is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * noclvag is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with noclvag.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Some functions based on:
 * https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.h */
/* Copyright (c) 2017, 2021 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include "util.h"

const char hex_charset[] = "0123456789abcdefABCDEF";
const char bech32_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const char bech32mask_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l.";

static uint32_t _bech32_polymod_step(uint32_t pre) {
  uint8_t b = pre >> 25;
  return ((pre & 0x1FFFFFF) << 5) ^ (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
         (-((b >> 1) & 1) & 0x26508e6dUL) ^ (-((b >> 2) & 1) & 0x1ea119faUL) ^
         (-((b >> 3) & 1) & 0x3d4233ddUL) ^ (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1, -1};

static int _convert_bits(uint8_t* output, size_t* output_len,
                         const uint8_t output_bits, const uint8_t* input,
                         size_t input_len, const uint8_t input_bits) {
  uint32_t val = 0;
  int bits = 0;
  uint32_t output_mask = (((uint32_t)1) << output_bits) - 1;
  uint32_t input_mask = (((uint32_t)1) << input_bits) - 1;

  /* We support up to 5 to 8 bits only */
  if ((input_bits < 5) || (input_bits > 8) || (output_bits < 5) ||
      (output_bits > 8)) {
    return -1;
  }

  if (input_len < 1) {
    return -1;
  }

  *output_len = 0;
  while (input_len > 0) {
    val = (val << input_bits);
    val |= ((*input) & input_mask);
    input++;
    bits += input_bits;

    while (bits >= output_bits) {
      bits -= output_bits;
      output[*output_len] = (uint8_t)((val >> bits) & output_mask);
      (*output_len)++;
    }

    input_len--;
  }

  if (bits > 0) {
    output[*output_len] =
        (uint8_t)((val << (output_bits - bits)) & output_mask);
    (*output_len)++;
  }

  return 0;
}

void fprinthex(FILE* fp, const unsigned char* src, const size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    fprintf(fp, "%02X", src[i]);
  }
}

void printhex(const unsigned char* src, const size_t len) {
  fprinthex(stdout, src, len);
}

/** Encode a Bech32 string
 *
 * Converts an array of 8-bit values and an HRP string into a Bech32 encoded
 * string. Returns 0 if successful.
 */
int bech32_encode(char* output, const char* hrp, const uint8_t* input,
                  const size_t input_len) {
  uint8_t buf[96];
  size_t buf_len;
  uint32_t chk = 1;
  size_t i = 0;

  /* Some limits on input size, to be safe */
  if ((input_len < 1) || (input_len > 50) || (strlen(hrp) < 1) ||
      (strlen(hrp) > 10)) {
    return -1;
  }

  /* Convert 8-bit unsigned integers to 5-bit integers */
  if (_convert_bits(buf, &buf_len, 5, input, input_len, 8)) {
    return -1;
  }

  /* Do bech32 encoding */
  /* Process HRP */
  while (hrp[i] != 0) {
    int ch = hrp[i];

    /* Fail if HRP has non-allowed characters */
    if (ch < 33 || ch > 126) {
      return -1;
    }

    /* Fail if HRP has capital letters */
    if (ch >= 'A' && ch <= 'Z') {
      return -1;
    }

    /* Update checksum */
    chk = _bech32_polymod_step(chk) ^ (ch >> 5);

    i++;
  }

  /* Process HRP again */
  chk = _bech32_polymod_step(chk);
  while (*hrp != 0) {
    chk = _bech32_polymod_step(chk) ^ (*hrp & 0x1f);
    *(output) = *(hrp);
    output++;
    hrp++;
  }
  /* Add HRP separator */
  *output = '1';
  output++;

  /* Process input */
  for (i = 0; i < buf_len; i++) {
    /* Fail if input has more than 5 bits of data */
    if (buf[i] >> 5) {
      return -1;
    }

    /* Update checksum and convert input */
    chk = _bech32_polymod_step(chk) ^ buf[i];
    *output = bech32_charset[buf[i]];
    output++;
  }

  /* Write the checksum part */
  for (i = 0; i < 6; i++) {
    chk = _bech32_polymod_step(chk);
  }
  chk ^= 1;
  for (i = 0; i < 6; i++) {
    *output = bech32_charset[(chk >> ((5 - i) * 5)) & 0x1f];
    output++;
  }

  /* Add null terminator at the end */
  *output = '\0';

  return 0;
}

/** Decode a Bech32 string
 *
 * Converts a Bech32 encoded string into an array of 8-bit values and an HRP
 * string. Not 100% Bech32 conformant. Returns 0 if successful.
 */
int bech32_decode(uint8_t* output, size_t* output_len, char* hrp,
                  const char* input, const size_t input_len) {
  uint8_t buf[96];
  uint32_t chk = 1;
  size_t i;
  size_t hrp_len;

  /* Some limits on input length */
  if ((input_len < 9) || (input_len > 64)) {
    return -1;
  }

  /* Find HRP separator */
  hrp_len = input_len;
  while ((hrp_len > 1) && (input[hrp_len - 1] != '1')) {
    hrp_len--;
  }
  if (hrp_len < 1) {
    return -1;
  }

  /* Process HRP */
  for (i = 0; i < hrp_len; i++) {
    int ch = input[i];

    /* Only values allowed are 33 - 126 */
    if ((ch < 33) || (ch > 126)) {
      return -1;
    }

    /* Only lower case allowed */
    if (ch >= 'A' && ch <= 'Z') {
      return -1;
    }
    hrp[i] = ch;
    chk = _bech32_polymod_step(chk) ^ (ch >> 5);
  }
  /* Write HRP null terminator */
  hrp[i] = '\0';

  chk = _bech32_polymod_step(chk);
  for (i = 0; i < hrp_len; i++) {
    chk = _bech32_polymod_step(chk) ^ (input[i] & 0x1f);
  }
  /* Skip HRP separator */
  i++;

  while (i < input_len) {
    int ch = input[i];

    /* Only lower case allowed */
    if (ch >= 'A' && ch <= 'Z') {
      return -1;
    }

    /* Convert character */
    int8_t v = (ch & 0x80) ? -1 : charset_rev[ch];

    /* Invalid character */
    if (v == -1) {
      return -1;
    }

    chk = (uint32_t)(_bech32_polymod_step(chk) ^ v);

    if (i < (input_len - 6)) {
      buf[i - (hrp_len + 1)] = (uint8_t)v;
    }

    i++;
  }

  /* Invalid checksum */
  if (chk != 1) {
    return -1;
  }

  /* Convert 5-bit integers to 8-bit unsigned integers */
  return _convert_bits(output, output_len, 8, buf, i, 5);
}

/** Decode a Bech32 partial string
 *
 * Converts a partial Bech32 encoded string without HRP, HRP separator and
 * checksum into an array of 8-bit values. Returns 0 on success.
 */
int bech32_partial_decode(uint8_t* output, uint8_t* output_mask,
                          size_t* output_len, const char* input,
                          const size_t input_len) {
  uint8_t buf[96];
  uint8_t mask_buf[96];
  size_t i;

  /* Some limits on input size, to be safe */
  if ((input_len < 1) || (input_len > 55)) {
    return -1;
  }

  /* Decode bech32 to 5-bit unsigned integers */
  for (i = 0; i < input_len; i++) {
    /* Capital letters not allowed */
    if (input[i] >= 'A' && input[i] <= 'Z') {
      return -1;
    }

    int8_t v;
    if (input[i] == '.') {
      mask_buf[i] = 0x00;
      v = 0;
    } else {
      mask_buf[i] = 0x1f;

      /* Convert character to 5-bit equivalent */
      v = (input[i] & 0x80) ? -1 : charset_rev[(int8_t)input[i]];
    }

    /* Invalid character */
    if (v == -1) {
      return -1;
    }

    buf[i] = (uint8_t)v;
  }

  // Convert 5-bit unsigned integers to 8-bit unsigned integers
  int ret = _convert_bits(output_mask, output_len, 8, mask_buf, i, 5);
  if (ret != 0) {
    return ret;
  }

  return _convert_bits(output, output_len, 8, buf, i, 5);
}

int count_processors(void) {
  FILE* fp;
  char buf[512];
  int count = 0;

  fp = fopen("/proc/cpuinfo", "r");
  if (!fp) {
    return -1;
  }

  while (fgets(buf, sizeof(buf), fp)) {
    if (!strncmp(buf, "processor\t", 10)) {
      count += 1;
    }
  }
  fclose(fp);

  return count;
}

static const char hexdig[] = "0123456789abcdef";

// An example:
// input: hex[4] = {0x31, 0x32, 0x61, 0x62}
// output: bin[2] = {0x12, 0xab}
int hex_decode(uint8_t* bin, size_t* binszp, const char* hex, size_t hexsz) {
  size_t binsz = *binszp;
  const unsigned char* hexu = (const unsigned char*)hex;
  size_t i;

  /* hexsz must be even */
  if (hexsz & 1) {
    return -1;
  }

  /* Skip '0x' prefix if detected */
  if (*hexu == '0' && (hexu[1] | 0x20) == 'x') {
    hexu += 2;
    hexsz -= 2;
  }

  /* Validate sizes */
  if (hexsz == 0 || binsz < hexsz / 2) {
    return -1;
  }

  binsz = hexsz / 2;
  for (i = 0; i < binsz; i++, bin++) {
    if (!isxdigit(*hexu)) {
      return -1;
    }
    if (isdigit(*hexu)) {
      *bin = (*hexu - '0') << 4;
    } else {
      *bin = ((*hexu | 0x20) - 'a' + 10) << 4;
    }
    hexu++;
    if (!isxdigit(*hexu)) {
      return -1;
    }
    if (isdigit(*hexu)) {
      *bin |= (*hexu - '0');
    } else {
      *bin |= ((*hexu | 0x20) - 'a' + 10);
    }
    hexu++;
  }

  *binszp = binsz;

  return 0;
}

// An example:
// input: bin[2] = {0x12, 0xab}
// output: hex[4] = {0x31, 0x32, 0x61, 0x62}
int hex_encode(char* hex, size_t* hexszp, const uint8_t* bin, size_t binsz) {
  size_t i, len;
  if (*hexszp < binsz * 2) {
    return -1;
  }

  len = 0;
  for (i = 0; i < binsz; i++, bin++) {
    *hex++ = hexdig[*bin >> 4];
    len++;
    *hex++ = hexdig[*bin & 0xf];
    len++;
  }
  *hexszp = len;

  return 0;
}

// Like memcpy, but length specified in bits (rather than bytes)
void copy_nbits(uint8_t* dst, uint8_t* src, size_t nbits) {
  // An example:
  // dst(input):  MMMMMMMM NNNNNNNN
  // src:         IIIIIIII JJJJJJJJ
  // nbits: 11
  // dst(output): IIIIIIII JJJNNNNN
  size_t nbytes = (nbits / 8) + 1;
  size_t extra_nbits = (nbytes * 8) - nbits;
  const uint8_t tab[9] = {
      0b00000000, /* 0 bits 1 */
      0b00000001, /* 1 bit 1  */
      0b00000011, /* 2 bits 1 */
      0b00000111, /* 3 bits 1 */
      0b00001111, /* 4 bits 1 */
      0b00011111, /* 5 bits 1 */
      0b00111111, /* 6 bits 1 */
      0b01111111, /* 7 bits 1 */
      0b11111111, /* 8 bits 1 */
  };
  uint8_t backup = dst[nbytes - 1]; // NNNNNNNN
  memcpy(dst, src, nbytes);
  uint8_t after = dst[nbytes - 1];                   // JJJJJJJJ
  dst[nbytes - 1] = (backup & tab[extra_nbits])      // 000NNNNN
                    | (after & (~tab[extra_nbits])); // JJJ00000
}

/*
 * Some functions based on
 * https://github.com/bitcoin-core/secp256k1/tree/master/examples
 */

/* Returns 1 on success, and 0 on failure. */
int noclvag_fill_random(unsigned char* data, size_t size) {
  ssize_t res = getrandom(data, size, 0);
  if (res < 0 || (size_t)res != size) {
    return -1;
  } else {
    return 0;
  }

  return -1;
}

/* Cleanses memory to prevent leaking sensitive info. Won't be optimized out. */
void noclvag_secure_erase(void* ptr, size_t len) {
  /* We use a memory barrier that scares the compiler away from optimizing out
   * the memset.
   *
   * Quoting Adam Langley <agl@google.com> in commit
   * ad1907fe73334d6c696c8539646c21b11178f20f in BoringSSL (ISC License): As
   * best as we can tell, this is sufficient to break any optimisations that
   *    might try to eliminate "superfluous" memsets.
   * This method used in memzero_explicit() the Linux kernel, too. Its advantage
   * is that it is pretty efficient, because the compiler can still implement
   * the memset() efficiently, just not remove it entirely. See "Dead Store
   * Elimination (Still) Considered Harmful" by Yang et al. (USENIX Security
   * 2017) for more background.
   */
  memset(ptr, 0, len);
  __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

void noclvag_put_hex_col(FILE* file_ptr, const uint8_t* buf, const size_t len) {
  for (size_t i = 0; i < len; i++) {
    fprintf(file_ptr, "%02X", buf[i]);
  }
  fputc(',', file_ptr);
}

/* Get a hex string of len bytes (characters / 2) and put it in buf as binary */
int noclvag_get_hex_col(FILE* file_ptr, uint8_t* buf, size_t* len) {
  int ch;
  size_t i = 0;

  /* We need to read the comma also */
  while (i <= *len) {
    /* First nibble */
    ch = fgetc(file_ptr);
    /* fputc(ch, stderr); */
    if (ch == ',') {
      break;
    } else if (ch == EOF || isxdigit(ch) == 0) {
      return -1;
    }

    if (isdigit(ch)) {
      buf[i] = ((ch - '0') << 4);
    } else {
      buf[i] = (((ch | 0x20) - 'a' + 10) << 4);
    }

    /* Second nibble */
    ch = fgetc(file_ptr);
    if (ch == EOF || isxdigit(ch) == 0) {
      return -1;
    }
    if (isdigit(ch)) {
      buf[i] |= (ch - '0');
    } else {
      buf[i] |= ((ch | 0x20) - 'a' + 10);
    }

    i++;
  }

  if (i < 1) {
    return -1;
  }
  *len = i;

  return 0;
}

void noclvag_put_response_row(const char* filename,
                              const noclvag_response_row* row_ptr) {
  /* TODO: handle existing files gracefully */
  FILE* file_ptr;

  assert(row_ptr->pattern_len <= NOCLVAG_PATTERN_MAX_LEN);

  if (filename == NULL) {
    filename = NOCLVAG_RESPONSE_FILENAME;
  }
  file_ptr = fopen(filename, "ab+");

  /* Write pattern hex */
  noclvag_put_hex_col(file_ptr, row_ptr->pattern, row_ptr->pattern_len);

  /* Write pattern mask */
  noclvag_put_hex_col(file_ptr, row_ptr->pattern_mask, row_ptr->pattern_len);

  /* Write compressed public key */
  noclvag_put_hex_col(file_ptr, row_ptr->cpubkey1, sizeof(row_ptr->cpubkey1));

  /* Write secret key2 */
  noclvag_put_hex_col(file_ptr, row_ptr->seckey2, sizeof(row_ptr->seckey2));

  fputc('\n', file_ptr);
  fclose(file_ptr);
}
