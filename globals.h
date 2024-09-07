/*
 * noclvag, Nostr OpenCL Vanity Address Generator.
 * Copyright (C) 2024 alex0jsan <nostr:npub1alex0jsan7wt5aq7exv9je9qlvdwm69sr7u6m8msjr77xv6yj60qkp8462>
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

#if !defined(__NOCLVAG_GLOBALS_H__)
#define __NOCLVAG_GLOBALS_H__ 1

#include <stdint.h>

#define NOCLVAG_SECKEY_LEN 32  /* Secret key length in bytes */
#define NOCLVAG_PUBKEY_LEN 32  /* Nostr public key length in bytes */
#define NOCLVAG_CPUBKEY_LEN 33 /* Compressed EC public key length in bytes */
#define NOCLVAG_PATTERN_MAX_LEN 32 /* Same as public key length */

#define NOCLVAG_SECRETS_FILENAME "noclvag-secrets.txt"
#define NOCLVAG_REQUEST_FILENAME "noclvag-request.txt"
#define NOCLVAG_RESPONSE_FILENAME "noclvag-response.txt"

typedef struct {
  uint8_t pattern[NOCLVAG_PATTERN_MAX_LEN];
  size_t pattern_len;
  uint8_t pattern_mask[NOCLVAG_PATTERN_MAX_LEN];
  uint8_t cpubkey1[NOCLVAG_CPUBKEY_LEN];
} noclvag_request_row;

typedef struct {
  uint8_t pattern[NOCLVAG_PATTERN_MAX_LEN];
  size_t pattern_len;
  uint8_t pattern_mask[NOCLVAG_PATTERN_MAX_LEN];
  uint8_t cpubkey1[NOCLVAG_CPUBKEY_LEN];
  uint8_t seckey2[NOCLVAG_SECKEY_LEN];
} noclvag_response_row;

#endif /* !defined (__NOCLVAG_GLOBALS_H__) */
