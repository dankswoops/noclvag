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

#if !defined(__NOCLVAG_UTIL_H__)
#define __NOCLVAG_UTIL_H__ 1

#include "globals.h"

#include <stdint.h>
#include <stdio.h>

extern const char hex_charset[];
extern const char bech32_charset[];
extern const char bech32mask_charset[];

extern void fprinthex(FILE* fp, const unsigned char* src, size_t len);
extern void printhex(const unsigned char* src, size_t len);

extern int bech32_partial_decode(uint8_t* output, uint8_t* output_mask,
                                 size_t* output_len, const char* input,
                                 const size_t input_len);

extern int bech32_encode(char* output, const char* hrp, const uint8_t* input,
                         const size_t input_len);

extern int bech32_decode(uint8_t* output, size_t* output_len, char* hrp,
                         const char* input, const size_t input_len);

extern void noclvag_secure_erase(void* ptr, size_t len);
extern int noclvag_fill_random(unsigned char* data, size_t size);

extern int count_processors(void);

extern int hex_decode(uint8_t* bin, size_t* binszp, const char* hex,
                      size_t hexsz);
extern int hex_encode(char* hex, size_t* hexszp, const uint8_t* bin,
                      size_t binsz);

extern void copy_nbits(uint8_t* dst, uint8_t* src, size_t nbits);
extern int noclvag_get_hex_col(FILE* file_ptr, uint8_t* buf, size_t* len);
extern void noclvag_put_hex_col(FILE* file_ptr, const uint8_t* buf,
                                const size_t len);
extern void noclvag_put_response_row(const char* filename,
                                     const noclvag_response_row* row_ptr);

#endif /* !defined (__NOCLVAG_UTIL_H__) */
