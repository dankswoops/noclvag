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

#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "globals.h"
#include "util.h"

#define NAME "noclvag-tool"
#define VERSION "0.1"

typedef struct {
  uint8_t pattern[NOCLVAG_PATTERN_MAX_LEN];
  size_t pattern_len;
  uint8_t pattern_mask[NOCLVAG_PATTERN_MAX_LEN];
  uint8_t cpubkey1[NOCLVAG_CPUBKEY_LEN];
  uint8_t seckey1[NOCLVAG_SECKEY_LEN];
} noclvag_secrets_row;

static void op_usage(const char* name) {
  fprintf(
      stderr,
      "Usage: %s [OPTIONS] --step1 PATTERN\n"
      "       %s [OPTIONS] --step3\n"
      "       %s [OPTIONS] -g\n"
      "       %s [OPTIONS] -c SECKEY\n"
      "       %s [OPTIONS] -C SECKEY1,SECKEY2\n"
      "       %s -h\n"
      "\n"
      "Operations:\n"
      "  -1, --step1 PATTERN\n"
      "                Generate a secret key and a noclvag-search request file "
      "from\n"
      "                pattern.\n"
      "\n"
      "  -3, --step3   Combine secret keys in secrets file and response file "
      "to\n"
      "                produce the final key.\n"
      "\n"
      "  -h, --help    Print more help text.\n"
      "\n"
      "Advanced operations:\n"
      "  -g, --generate\n"
      "                Generate a Nostr key pair.\n"
      "\n"
      "  -c, --convert SECKEY\n"
      "                Convert secret key to public key.\n"
      "\n"
      "  -C, --combine SECKEY1,SECKEY2\n"
      "                Combine split-key secret keys.\n"
      "\n"
      "Step 1 options:\n"
      "  -k, --key SECKEY\n"
      "                Use secret key instead of generating one.\n"
      "\n"
      "Global options:\n"
      "  -v, --verbose\n"
      "                Produce more verbose output.\n"
      "\n",
      name, name, name, name, name, name);
}

static void op_help(const char* name) {
  op_usage(name);
  fprintf(
      stderr,
      "Typical usage:\n"
      "  noclvag uses the split-key method to allow a third-party to search "
      "for a\n"
      "  secret key for you in a (hopefully) safe manner. More details about "
      "the\n"
      "  split-key method can be found in JeanLucPons's VanitySearch "
      "documentation.\n"
      "\n"
      "  To generate a Nostr vanity address, run the --step1 operation of "
      "this\n"
      "  tool on a secure, air-gapped PC, with the desired pattern (hex or "
      "npub).\n"
      "  For example, for a Nostr npub key starting with \"test\", run:\n"
      "    %s --step1 npub1test\n"
      "\n"
      "  This will generate a secret key, save it to a secrets file\n"
      "  (\"./%s\" by default) and generate \n"
      "  a request file (\"./%s\" by default).\n"
      "\n"
      "  Alternatively, you might want to generate a private key somewhere "
      "else\n"
      "  (e.g. greenart7c3's Amber Android app) and use that as the first "
      "secret key\n"
      "  instead. For that, you can use the --key option (with a hex or "
      "nsec key),\n"
      "  like this:\n"
      "    %s --step1 npub1test --key nsec1...\n"
      "\n"
      "  Now send the generated request file to a PC with a fast GPU and run\n"
      "  the --step2 operation of the noclvag-search tool. More documentation\n"
      "  can be found "
      "in that tool's help.\n"
      "\n"
      "  Once the key is found on the GPU PC, copy back the response file\n"
      "  (\"./%s\" by default) and run the --step3 operation of this\n"
      "  tool, like this:\n"
      "    %s --step3\n"
      "\n"
      "  The tool will put together the first and second secret keys and\n"
      "  check if the resulting public key matches the pattern. This,\n"
      "  unfortunately, can fail, and you'll have to try again from step2\n"
      "  or step1.\n"
      "\n"
      "  If the public key matches the pattern, the tool will print the new\n"
      "  secret key and public key in hex and bech32 (nsec, npub) formats. Be\n"
      "  sure to write down the secret key, and use it in your favourite "
      "Nostr\n"
      "  app or signing device (e.g. Amber).\n"
      "  And finally, be sure to securely purge the files.\n"
      "\n"
      // clang-format off
      /* Not implemented yet */
      /* "Complex patterns:\n"
      "  noclvag supports using a \".\" character as a wildcard, so that a "
      "pattern\n"
      "  that isn't strictly a prefix can be searched for.\n"
      "\n"
      "  Please note that noclvag does not support npub patterns longer than\n"
      "  50 characters, excluding the \"npub1\" part.\n"
      "\n"
      "  For example, to search for an npub that starts with \"q\", its third "
      "\n"
      "  character is \"p\" and the other characters can be anything, use:\n"
      "    %s --step1 npub1q.p\n"
      "\n" */
      // clang-format on
      "Enjoy, and stay free.\n"
      "\n",
      name, NOCLVAG_SECRETS_FILENAME, NOCLVAG_REQUEST_FILENAME, name,
      NOCLVAG_RESPONSE_FILENAME, name, name);
}

static void validate_charset(const char* input_key, const size_t input_key_len,
                             const size_t input_key_offset,
                             const char* charset) {
  for (size_t i = input_key_offset; i < input_key_len; i++) {
    if (strchr(charset, input_key[i]) == NULL) {
      fprintf(stderr, "FATAL: Invalid character in key.\n");
      fprintf(stderr, "FATAL: Valid characters are: %s\n", charset);
      fprintf(stderr,
              "FATAL: Please fix the invalid character and try again.\n");
      fprintf(stderr, "FATAL: Key:       %s\n", input_key);
      fprintf(stderr, "FATAL: Check here ");
      for (size_t ii = 0; ii < i; ii++) {
        fprintf(stderr, "_");
      }
      fprintf(stderr, "^\n");
      exit(1);
    }
  }
}

static void print_seckey(const unsigned char* const seckey_bin,
                         const size_t seckey_bin_len) {
  char nsec_str[96];

  /* Convert binary private key to bech32 address with "nsec" hrp */
  assert(bech32_encode(nsec_str, "nsec", seckey_bin, seckey_bin_len) == 0);
  printf("Private key (nsec): %s\n", nsec_str);
  printf("Private key (hex): ");
  printhex(seckey_bin, seckey_bin_len);
  printf("\n");

  noclvag_secure_erase(nsec_str, sizeof(nsec_str));
}

static void print_pubkey(const unsigned char* const pubkey_bin,
                         const size_t pubkey_bin_len) {
  char npub_str[96];

  /* Convert binary public key to bech32 address with "npub" hrp */
  assert(bech32_encode(npub_str, "npub", pubkey_bin, pubkey_bin_len) == 0);
  printf("Public key (npub): %s\n", npub_str);
  printf("Public key (hex): ");
  printhex(pubkey_bin, pubkey_bin_len);
  printf("\n");
}

static void op_generate_keypair() {
  fprintf(stderr, "INFO: Generating new Nostr key pair...\n\n");
  unsigned char seckey_bin[NOCLVAG_SECKEY_LEN];
  unsigned char pubkey_bin[NOCLVAG_PUBKEY_LEN];
  unsigned char randomize[32];
  secp256k1_xonly_pubkey xonly_pubkey;
  secp256k1_keypair keypair;

  /* Before we can call actual API functions, we need to create a "context". */
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (noclvag_fill_random(randomize, sizeof(randomize))) {
    fprintf(stderr,
            "FATAL: Failed to generate randomness. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Randomizing the context is recommended to protect against side-channel
   * leakage See `secp256k1_context_randomize` in secp256k1.h for more
   * information about it. This should never fail. */
  assert(secp256k1_context_randomize(ctx, randomize));

  /*** Key Generation ***/

  /* If the secret key is zero or out of range (bigger than secp256k1's
   * order), we try to sample a new key. Note that the probability of this
   * happening is negligible. */
  while (1) {
    if (noclvag_fill_random(seckey_bin, sizeof(seckey_bin))) {
      fprintf(stderr,
              "FATAL: Failed to generate randomness. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      exit(1);
    }

    if (secp256k1_keypair_create(ctx, &keypair, seckey_bin) == 1) {
      /*  Returns: 1: secret was valid, keypair is ready to use */
      break;
    }
  }

  /* Generate X-coordinate only public key */
  /* Returns: 1 always. */
  assert(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, NULL, &keypair) == 1);

  /* Serialize X-only public key to binary */
  /* Returns: 1 always. */
  assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey_bin, &xonly_pubkey) == 1);

  /* Print key pair */
  print_pubkey(pubkey_bin, sizeof(pubkey_bin));
  print_seckey(seckey_bin, sizeof(seckey_bin));

  /* It's best practice to try to clear secrets from memory after using them.
   * This is done because some bugs can allow an attacker to leak memory, for
   * example through "out of bounds" array access (see Heartbleed), Or the OS
   * swapping them to disk. Hence, we overwrite the secret key buffer with
   * zeros.
   *
   * Here we are preventing these writes from being optimized out, as any good
   * compiler will remove any writes that aren't used. */
  noclvag_secure_erase(&keypair, sizeof(keypair));
  noclvag_secure_erase(seckey_bin, sizeof(seckey_bin));
}

static void op_convert_key(char* const input_key) {
  fprintf(stderr, "INFO: Converting input private key...\n\n");

  unsigned char seckey_bin[NOCLVAG_SECKEY_LEN];
  unsigned char pubkey_bin[NOCLVAG_PUBKEY_LEN];
  unsigned char randomize[32];
  secp256k1_xonly_pubkey xonly_pubkey;
  secp256k1_keypair keypair;
  size_t input_key_len = strlen(input_key);

  /* Find input key format and convert to binary */
  if (strncmp(input_key, "nsec1", 5) == 0) {
    fprintf(stderr, "INFO: Assuming input key format: nsec.\n");
    size_t input_key_offset = 5;

    validate_charset(input_key, input_key_len, input_key_offset,
                     bech32_charset);

    char hrp[10];
    size_t seckey_len;
    if ((bech32_decode(seckey_bin, &seckey_len, hrp, input_key,
                       input_key_len) != 0) ||
        (seckey_len != sizeof(seckey_bin))) {
      fprintf(stderr,
              "FATAL: Failed to convert key to binary. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      exit(1);
    }
  } else {
    fprintf(stderr, "INFO: Assuming input key format: hex.\n");
    size_t input_key_offset = 0;

    if (strncmp(input_key, "0x", 2) == 0) {
      input_key_offset = 2;
    }

    if ((input_key_len - input_key_offset) != 64) {
      fprintf(stderr,
              "FATAL: Invalid input key. Too short. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      exit(1);
    }

    validate_charset(input_key, input_key_len, input_key_offset, hex_charset);

    size_t seckey_len = sizeof(seckey_bin);

    if (hex_decode(seckey_bin, &seckey_len, &input_key[input_key_offset],
                   input_key_len - input_key_offset) != 0) {
      fprintf(stderr,
              "FATAL: Failed to convert key to binary. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      exit(1);
    }
  }

  /* Create and randomize context. */
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (noclvag_fill_random(randomize, sizeof(randomize))) {
    fprintf(stderr,
            "FATAL: Failed to generate randomness. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }
  assert(secp256k1_context_randomize(ctx, randomize));

  /* Validate secret key. */
  if (secp256k1_keypair_create(ctx, &keypair, seckey_bin) != 1) {
    /*  Returns: 1: secret was valid, keypair is ready to use */
    fprintf(stderr, "FATAL: Invalid private key. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Generate X-coordinate only public key */
  /* Returns: 1 always. */
  assert(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, NULL, &keypair) == 1);

  /* Serialize X-only public key to binary */
  /* Returns: 1 always. */
  assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey_bin, &xonly_pubkey) == 1);

  /* Print key pair. */
  print_pubkey(pubkey_bin, sizeof(pubkey_bin));
  print_seckey(seckey_bin, sizeof(seckey_bin));

  /* Clear secrets from memory. */
  noclvag_secure_erase(&keypair, sizeof(keypair));
  noclvag_secure_erase(seckey_bin, sizeof(seckey_bin));
  noclvag_secure_erase(input_key, input_key_len);
}

static void op_combine_keys(char* const input_keys, const bool verbose) {
  fprintf(stderr, "INFO: Combining input private keys...\n\n");
  char input_keys_arr[2][96];
  unsigned char seckeys_bin_arr[3][NOCLVAG_SECKEY_LEN];
  unsigned char pubkey_bin[NOCLVAG_PUBKEY_LEN];
  unsigned char randomize[32];
  secp256k1_xonly_pubkey xonly_pubkey;
  secp256k1_keypair keypair;
  size_t input_keys_len = strlen(input_keys);

  /* Separate input keys */
  {
    if (input_keys_len < 125 || input_keys_len > 129) {
      fprintf(stderr,
              "FATAL: Invalid input keys. Too short or too long. (Debug "
              "info:%s:%d)\n",
              __FILE__, __LINE__);
      exit(1);
    }

    /* Find separator comma */
    char* sep_ptr = strchr(input_keys, ',');
    if (sep_ptr == NULL) {
      fprintf(
          stderr,
          "FATAL: Invalid input keys format. Format should be: key1,key2\n");
      exit(1);
    }

    ssize_t sep_pos = sep_ptr - input_keys;
    if (sep_pos < 62 || sep_pos > 96) {
      fprintf(stderr,
              "FATAL: Invalid input keys. One of the keys is too short "
              "or too long. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      exit(1);
    }

    memcpy(input_keys_arr[0], input_keys, sep_pos);
    input_keys_arr[0][sep_pos] = '\0';

    memcpy(input_keys_arr[1], sep_ptr + 1, input_keys_len - sep_pos - 1);
    input_keys_arr[1][input_keys_len - sep_pos - 1] = '\0';
  }

  /* Validate input keys and convert to binary */
  for (int key_idx = 0; key_idx < 2; key_idx++) {
    fprintf(stderr, "INFO: Processing input key %d.\n", key_idx + 1);
    size_t input_key_len;
    size_t input_key_offset = 0;

    input_key_len = strlen(input_keys_arr[key_idx]);
    /* Find input key format and convert to binary */
    if (strncmp(input_keys_arr[key_idx], "nsec1", 5) == 0) {
      fprintf(stderr, "INFO: Assuming input key format: nsec.\n");
      input_key_offset = 5;

      /* Validate character set */
      validate_charset(input_keys_arr[key_idx], input_key_len, input_key_offset,
                       bech32_charset);

      char hrp[10];
      size_t seckey_len;
      if ((bech32_decode(seckeys_bin_arr[key_idx], &seckey_len, hrp,
                         input_keys_arr[key_idx], input_key_len) != 0) ||
          (seckey_len != sizeof(seckeys_bin_arr[0]))) {
        fprintf(stderr,
                "FATAL: Failed to convert key to binary. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        exit(1);
      }
    } else {
      fprintf(stderr, "INFO: Assuming input key format: hex.\n");

      if (strncmp(input_keys_arr[key_idx], "0x", 2) == 0) {
        input_key_offset = 2;
      }

      if ((input_key_len - input_key_offset) != 64) {
        fprintf(stderr,
                "FATAL: Invalid input key. Too short. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        exit(1);
      }

      /* Validate character set */
      validate_charset(input_keys_arr[key_idx], input_key_len, input_key_offset,
                       hex_charset);

      size_t seckey_len = sizeof(seckeys_bin_arr[0]);
      if (hex_decode(seckeys_bin_arr[key_idx], &seckey_len,
                     &input_keys_arr[key_idx][input_key_offset],
                     input_key_len - input_key_offset) != 0) {
        fprintf(stderr,
                "FATAL: Failed to convert key to binary. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        exit(1);
      }
    }
    if (verbose) {
      print_seckey(seckeys_bin_arr[key_idx], sizeof(seckeys_bin_arr[key_idx]));
      printf("\n");
    }
  }

  /*** Key combination ***/

  /* Create and randomize context. */
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (noclvag_fill_random(randomize, sizeof(randomize))) {
    fprintf(stderr,
            "FATAL: Failed to generate randomness. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }
  assert(secp256k1_context_randomize(ctx, randomize));

  /* If the secret key is zero or out of range (bigger than secp256k1's
   * order) then it's invalid. */
  if (secp256k1_keypair_create(ctx, &keypair, seckeys_bin_arr[0]) != 1) {
    /*  Returns: 1: secret was valid, keypair is ready to use */
    fprintf(stderr, "FATAL: First private key is invalid. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  // Before tweaking
  fprintf(stderr, "Beofre tweaking\n");
  /* Generate X-coordinate only public key */
  /* Returns: 1 always. */
  assert(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, NULL, &keypair) == 1);

  /* Serialize X-only public key to binary */
  /* Returns: 1 always. */
  assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey_bin, &xonly_pubkey) == 1);

  print_pubkey(pubkey_bin, sizeof(pubkey_bin));
  print_seckey(seckeys_bin_arr[0], sizeof(seckeys_bin_arr[0]));

  fprintf(stderr, "After tweaking\n");
  /*  Returns: 0 if the arguments are invalid or the resulting keypair would be
   *           invalid (only when the tweak is the negation of the keypair's
   *           secret key). 1 otherwise. */
  if (secp256k1_keypair_xonly_tweak_add(ctx, &keypair, seckeys_bin_arr[1]) ==
      0) {
    fprintf(stderr, "FATAL: Failed to add keys. (Debug info:%s:%d)\n", __FILE__,
            __LINE__);
    exit(1);
  }
  /* Generate X-coordinate only public key */
  /* Returns: 1 always. */
  assert(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, NULL, &keypair) == 1);

  /* Serialize X-only public key to binary */
  /* Returns: 1 always. */
  assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey_bin, &xonly_pubkey) == 1);

  /* Returns: 1 always. */
  assert(secp256k1_keypair_sec(ctx, seckeys_bin_arr[2], &keypair) == 1);

  print_pubkey(pubkey_bin, sizeof(pubkey_bin));
  print_seckey(seckeys_bin_arr[2], sizeof(seckeys_bin_arr[2]));

  /* Clear secrets from memory. */
  noclvag_secure_erase(&keypair, sizeof(keypair));
  noclvag_secure_erase(seckeys_bin_arr, sizeof(seckeys_bin_arr));
  noclvag_secure_erase(input_keys_arr, sizeof(input_keys_arr));
  noclvag_secure_erase(input_keys, input_keys_len);
}

static void noclvag_put_secrets_row(const char* filename,
                                    const noclvag_secrets_row* row_ptr) {
  FILE* file_ptr;

  assert(row_ptr->pattern_len <= NOCLVAG_PATTERN_MAX_LEN);

  if (filename == NULL) {
    filename = NOCLVAG_SECRETS_FILENAME;
  }
  file_ptr = fopen(filename, "ab+");

  // TODO: handle existing files gracefully

  /* Write pattern hex */
  noclvag_put_hex_col(file_ptr, row_ptr->pattern, row_ptr->pattern_len);

  /* Write pattern mask */
  noclvag_put_hex_col(file_ptr, row_ptr->pattern_mask, row_ptr->pattern_len);

  /* Write compressed public key */
  noclvag_put_hex_col(file_ptr, row_ptr->cpubkey1, sizeof(row_ptr->cpubkey1));

  /* Write secret key1 */
  noclvag_put_hex_col(file_ptr, row_ptr->seckey1, sizeof(row_ptr->seckey1));

  fputc('\n', file_ptr);
  fclose(file_ptr);
}

static void noclvag_put_request_row(char* filename,
                                    noclvag_request_row* row_ptr) {
  FILE* file_ptr;

  assert(row_ptr->pattern_len <= NOCLVAG_PATTERN_MAX_LEN);

  if (filename == NULL) {
    filename = NOCLVAG_REQUEST_FILENAME;
  }
  file_ptr = fopen(filename, "ab+");

  // TODO: handle existing files gracefully

  /* Write pattern hex */
  noclvag_put_hex_col(file_ptr, row_ptr->pattern, row_ptr->pattern_len);

  /* Write pattern mask */
  noclvag_put_hex_col(file_ptr, row_ptr->pattern_mask, row_ptr->pattern_len);

  /* Write compressed public key */
  noclvag_put_hex_col(file_ptr, row_ptr->cpubkey1, sizeof(row_ptr->cpubkey1));

  fputc('\n', file_ptr);
  fclose(file_ptr);
}

static void noclvag_get_secrets_row(const char* filename,
                                    noclvag_secrets_row* row_ptr) {
  FILE* file_ptr;
  size_t len;

  if (filename == NULL) {
    filename = NOCLVAG_SECRETS_FILENAME;
  }
  file_ptr = fopen(filename, "rb");

  /* Read pattern */
  row_ptr->pattern_len = NOCLVAG_PATTERN_MAX_LEN;
  if (noclvag_get_hex_col(file_ptr, row_ptr->pattern,
                          &(row_ptr->pattern_len))) {
    fprintf(stderr,
            "FATAL: Incorrect secrets file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read pattern mask */
  len = row_ptr->pattern_len;
  if (noclvag_get_hex_col(file_ptr, row_ptr->pattern_mask, &len)) {
    fprintf(stderr,
            "FATAL: Incorrect secrets file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  if (len != row_ptr->pattern_len) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read compressed pubkey1 */
  len = NOCLVAG_CPUBKEY_LEN;
  if (noclvag_get_hex_col(file_ptr, row_ptr->cpubkey1, &len)) {
    fprintf(stderr,
            "FATAL: Incorrect secrets file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  if (len != NOCLVAG_CPUBKEY_LEN) {
    fprintf(stderr,
            "FATAL: Incorrect secrets file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read secret key1 */
  len = NOCLVAG_SECKEY_LEN;
  noclvag_get_hex_col(file_ptr, row_ptr->seckey1, &len);

  if (len != NOCLVAG_SECKEY_LEN) {
    fprintf(stderr,
            "FATAL: Incorrect secrets file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  fclose(file_ptr);
}

static void noclvag_get_response_row(const char* filename,
                                     noclvag_response_row* row_ptr) {
  FILE* file_ptr;
  size_t len;

  if (filename == NULL) {
    filename = NOCLVAG_RESPONSE_FILENAME;
  }
  file_ptr = fopen(filename, "rb");

  /* Read pattern */
  row_ptr->pattern_len = NOCLVAG_PATTERN_MAX_LEN;
  if (noclvag_get_hex_col(file_ptr, row_ptr->pattern,
                          &(row_ptr->pattern_len))) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read pattern mask */
  len = row_ptr->pattern_len;
  if (noclvag_get_hex_col(file_ptr, row_ptr->pattern_mask, &len)) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  if (len != row_ptr->pattern_len) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read compressed pubkey1 */
  len = sizeof(row_ptr->cpubkey1);
  if (noclvag_get_hex_col(file_ptr, row_ptr->cpubkey1, &len)) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  };

  if (len != sizeof(row_ptr->cpubkey1)) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read secret key2 */
  len = sizeof(row_ptr->seckey2);
  if (noclvag_get_hex_col(file_ptr, row_ptr->seckey2, &len)) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  if (len != sizeof(row_ptr->seckey2)) {
    fprintf(stderr,
            "FATAL: Incorrect response file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  fclose(file_ptr);
}

static void op_step1(const char* input_pattern, const char* input_key,
                     const bool versbose) {
  fprintf(stderr, "INFO: Performing step1.\n");

  secp256k1_context* ctx_ptr;
  secp256k1_keypair keypair;
  secp256k1_pubkey pubkey;
  unsigned char seckey_bin[NOCLVAG_SECKEY_LEN];
  unsigned char randomize[32];
  noclvag_secrets_row secrow;
  noclvag_request_row reqrow;

  /* Before we can call actual API functions, we need to create a "context". */
  ctx_ptr = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (noclvag_fill_random(randomize, sizeof(randomize))) {
    fprintf(stderr,
            "FATAL: Failed to generate randomness. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Randomizing the context is recommended to protect against side-channel
   * leakage See `secp256k1_context_randomize` in secp256k1.h for more
   * information about it. This should never fail. */
  assert(secp256k1_context_randomize(ctx_ptr, randomize));

  if (input_key) {
    size_t input_key_len = strlen(input_key);

    /* Find input key format and convert to binary */
    if (strncmp(input_key, "nsec1", 5) == 0) {
      fprintf(stderr, "INFO: Assuming input key format: nsec.\n");
      size_t input_key_offset = 5;

      validate_charset(input_key, input_key_len, input_key_offset,
                       bech32_charset);

      char hrp[10];
      size_t seckey_len;
      if ((bech32_decode(seckey_bin, &seckey_len, hrp, input_key,
                         input_key_len) != 0) ||
          (seckey_len != sizeof(seckey_bin))) {
        fprintf(stderr,
                "FATAL: Failed to convert key to binary. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        exit(1);
      }
    } else {
      fprintf(stderr, "INFO: Assuming input key format: hex.\n");
      size_t input_key_offset = 0;

      if (strncmp(input_key, "0x", 2) == 0) {
        input_key_offset = 2;
      }

      if ((input_key_len - input_key_offset) != (NOCLVAG_SECKEY_LEN * 2)) {
        fprintf(stderr,
                "FATAL: Invalid input key. Too short. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        exit(1);
      }

      validate_charset(input_key, input_key_len, input_key_offset, hex_charset);

      size_t seckey_len = sizeof(seckey_bin);
      if (hex_decode(seckey_bin, &seckey_len, &input_key[input_key_offset],
                     input_key_len - input_key_offset) != 0) {
        fprintf(stderr,
                "FATAL: Failed to convert key to binary. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        exit(1);
      }
    }
  } else {
    /* Generate key */

    /* If the secret key is zero or out of range (bigger than secp256k1's
     * order), we try to sample a new key. Note that the probability of this
     * happening is negligible. */
    while (1) {
      if (noclvag_fill_random(seckey_bin, sizeof(seckey_bin))) {
        fprintf(stderr,
                "FATAL: Failed to generate randomness. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        exit(1);
      }

      /*  Returns: 1: secret was valid, keypair is ready to use
       *           0: secret was invalid, try again with a different secret */
      if (secp256k1_keypair_create(ctx_ptr, &keypair, seckey_bin) == 1) {
        break;
      }
    }
  }

  /*  Returns: 1: secret was valid, keypair is ready to use
   *           0: secret was invalid, try again with a different secret */
  if (!secp256k1_keypair_create(ctx_ptr, &keypair, seckey_bin)) {
    fprintf(stderr, "FATAL: Invalid secret key. (Debug info:%s:%d)\n", __FILE__,
            __LINE__);
    exit(1);
  }

  /* Get the public key from a keypair. */
  /* Returns: 1 always. */
  assert(secp256k1_keypair_pub(ctx_ptr, &pubkey, &keypair));

  /* Serialize the pubkey in a compressed form(33 bytes). */
  /* Should always return 1. */
  size_t len = sizeof(secrow.cpubkey1);
  assert(secp256k1_ec_pubkey_serialize(ctx_ptr, secrow.cpubkey1, &len, &pubkey,
                                       SECP256K1_EC_COMPRESSED));
  /* Should be the same size as the size of the output, because we passed a
   * 33 byte array. */
  assert(len == sizeof(secrow.cpubkey1));

  /* Get the secret key from a keypair. */
  /* Returns: 1 always. */
  assert(secp256k1_keypair_sec(ctx_ptr, secrow.seckey1, &keypair));

  {
    /* Find pattern format and convert to binary */
    size_t input_pattern_len = strlen(input_pattern);
    if (strncmp(input_pattern, "npub1", 5) == 0) {
      fprintf(stderr, "INFO: Assuming pattern format: npub.\n");
      size_t input_pattern_offset = 5;

      validate_charset(input_pattern, input_pattern_len, input_pattern_offset,
                       bech32_charset);

      if (bech32_partial_decode(
              secrow.pattern, secrow.pattern_mask, &secrow.pattern_len,
              &input_pattern[input_pattern_offset],
              (input_pattern_len - input_pattern_offset)) != 0) {
        fprintf(
            stderr,
            "FATAL: Failed to convert pattern to binary. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
        exit(1);
      }
    } else {
      fprintf(stderr, "INFO: Assuming pattern format: hex.\n");
      size_t input_pattern_offset = 0;

      if (strncmp(input_pattern, "0x", 2) == 0) {
        input_pattern_offset = 2;
      }

      validate_charset(input_pattern, input_pattern_len, input_pattern_offset,
                       hex_charset);

      secrow.pattern_len = sizeof(secrow.pattern);
      if (hex_decode(secrow.pattern, &secrow.pattern_len,
                     &input_pattern[input_pattern_offset],
                     input_pattern_len - input_pattern_offset) != 0) {
        fprintf(
            stderr,
            "FATAL: Failed to convert pattern to binary. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
        exit(1);
      }
    }
  }

  reqrow.pattern_len = secrow.pattern_len;
  memcpy(reqrow.pattern, secrow.pattern, secrow.pattern_len);
  memcpy(reqrow.pattern_mask, secrow.pattern_mask, secrow.pattern_len);
  memcpy(reqrow.cpubkey1, secrow.cpubkey1, sizeof(secrow.cpubkey1));

  noclvag_put_secrets_row(NULL, &secrow);
  noclvag_put_request_row(NULL, &reqrow);

  /* It's best practice to try to clear secrets from memory after using them.
   * This is done because some bugs can allow an attacker to leak memory, for
   * example through "out of bounds" array access (see Heartbleed), Or the OS
   * swapping them to disk. Hence, we overwrite the secret key buffer with
   * zeros.
   *
   * Here we are preventing these writes from being optimized out, as any good
   * compiler will remove any writes that aren't used. */
  noclvag_secure_erase(&secrow, sizeof(secrow));
  noclvag_secure_erase(&keypair, sizeof(keypair));
  noclvag_secure_erase(seckey_bin, sizeof(seckey_bin));
}

static void op_step3(bool verbose) {
  secp256k1_context* ctx_ptr;
  secp256k1_keypair keypair;
  secp256k1_xonly_pubkey xonly_pubkey;
  unsigned char seckey_bin[NOCLVAG_SECKEY_LEN];
  unsigned char pubkey_bin[NOCLVAG_PUBKEY_LEN];
  unsigned char randomize[32];
  noclvag_response_row resrow;
  noclvag_secrets_row secrow;

  /*** Get and validate secrets row and response row ***/
  if (verbose) {
    fprintf(stderr, "INFO: Getting secrets row from file.\n");
  }
  noclvag_get_response_row(NULL, &resrow);

  if (verbose) {
    fprintf(stderr, "INFO: Getting response row from file.\n");
  }
  noclvag_get_secrets_row(NULL, &secrow);

  if ((secrow.pattern_len != resrow.pattern_len) ||
      memcmp(secrow.pattern, resrow.pattern, resrow.pattern_len) ||
      memcmp(secrow.pattern_mask, resrow.pattern_mask, resrow.pattern_len) ||
      memcmp(secrow.cpubkey1, resrow.cpubkey1, sizeof(resrow.cpubkey1))) {
    fprintf(stderr,
            "FATAL: Mismatch between secrets and response file. (Debug "
            "info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /*** Prepare secp256k1 stuff ***/

  /* Before we can call actual API functions, we need to create a "context". */
  ctx_ptr = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (noclvag_fill_random(randomize, sizeof(randomize))) {
    fprintf(stderr,
            "FATAL: Failed to generate randomness. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Randomizing the context is recommended to protect against side-channel
   * leakage. See `secp256k1_context_randomize` in secp256k1.h for more
   * information about it. This should never fail. */
  assert(secp256k1_context_randomize(ctx_ptr, randomize));

  /*** Tweak the secret key using addition first then check if pubkey matches
   * pattern ***/

  if (verbose) {
    fprintf(stderr, "INFO: Trying secret key tweaking using addition.\n");
  }
  memcpy(seckey_bin, secrow.seckey1, sizeof(secrow.seckey1));

  /** Tweak a secret key by adding tweak to it.
   * Returns: 0 if the arguments are invalid or the resulting secret key would
   * be invalid (only when the tweak is the negation of the secret key). 1
   * otherwise. */
  if (!secp256k1_ec_seckey_tweak_add(ctx_ptr, seckey_bin, resrow.seckey2)) {
    if (verbose) {
      fprintf(stderr, "INFO: Result is an invalid secret key.\n");
    }
    goto tweak_mul;
  }

  /** Compute the keypair for secret key.
   * Returns: 1: secret was valid, keypair is ready to use
   *          0: secret was invalid, try again with a different secret */
  if (!secp256k1_keypair_create(ctx_ptr, &keypair, seckey_bin)) {
    if (verbose) {
      fprintf(stderr, "INFO: Result is an invalid secret key.\n");
    }
    goto tweak_mul;
  } else {
    if (verbose) {
      fprintf(stderr, "INFO: Result is a valid secret key.\n");
    }
  }

  /** Get the x-only public key from a keypair.
   *  Returns: 1 always. */
  assert(secp256k1_keypair_xonly_pub(ctx_ptr, &xonly_pubkey, NULL, &keypair));

  /** Serialize an xonly_pubkey object into a 32-byte sequence.
   *  Returns: 1 always.   */
  assert(secp256k1_xonly_pubkey_serialize(ctx_ptr, pubkey_bin, &xonly_pubkey));

  if (verbose) {
    fprintf(stderr, "INFO: Tweaked public key: ");
    fprinthex(stderr, pubkey_bin, sizeof(pubkey_bin));
    fprintf(stderr, "\n");
  }

  for (size_t i = 0; i < secrow.pattern_len; i++) {
    if ((pubkey_bin[i] & secrow.pattern_mask[i]) !=
        (secrow.pattern[i] & secrow.pattern_mask[i])) {
      if (verbose) {
        fprintf(stderr, "INFO: Resulting public key doesn't match pattern.\n");
      }
      goto tweak_mul;
    }
  }

  print_seckey(seckey_bin, sizeof(seckey_bin));
  print_pubkey(pubkey_bin, sizeof(pubkey_bin));
  // TODO: Write to results file also
  return;

tweak_mul:
  /*** If we reach here then the pattern did not match, so we try tweaking by
   * multiplication ***/

  if (verbose) {
    fprintf(stderr, "INFO: Trying secret key tweaking using multiplication.\n");
  }
  memcpy(seckey_bin, secrow.seckey1, sizeof(secrow.seckey1));

  /** Tweak a secret key by multiplying it by a tweak.
   *  Returns: 0 if the arguments are invalid. 1 otherwise. */
  if (!secp256k1_ec_seckey_tweak_mul(ctx_ptr, seckey_bin, resrow.seckey2)) {
    if (verbose) {
      fprintf(stderr, "INFO: Result is an invalid secret key.\n");
    }
    goto tweak_failed;
  }

  /** Compute the keypair for secret key.
   *  Returns: 1: secret was valid, keypair is ready to use
   *           0: secret was invalid, try again with a different secret */
  if (!secp256k1_keypair_create(ctx_ptr, &keypair, seckey_bin)) {
    if (verbose) {
      fprintf(stderr, "INFO: Result is an invalid secret key.\n");
    }
    goto tweak_failed;
  } else {
    if (verbose) {
      fprintf(stderr, "INFO: Result is a valid secret key.\n");
    }
  }

  /** Get the x-only public key from a keypair.
   *  Returns: 1 always. */
  assert(secp256k1_keypair_xonly_pub(ctx_ptr, &xonly_pubkey, NULL, &keypair));

  /** Serialize an xonly_pubkey object into a 32-byte sequence.
   *  Returns: 1 always.   */
  assert(secp256k1_xonly_pubkey_serialize(ctx_ptr, pubkey_bin, &xonly_pubkey));

  if (verbose) {
    fprintf(stderr, "INFO: Tweaked public key: ");
    fprinthex(stderr, pubkey_bin, sizeof(pubkey_bin));
    fprintf(stderr, "\n");
  }

  for (size_t i = 0; i < secrow.pattern_len; i++) {
    if ((pubkey_bin[i] & secrow.pattern_mask[i]) !=
        (secrow.pattern[i] & secrow.pattern_mask[i])) {
      if (verbose) {
        fprintf(stderr, "INFO: Resulting public key doesn't match pattern.\n");
      }
      goto tweak_failed;
    }
  }

  print_seckey(seckey_bin, sizeof(seckey_bin));
  print_pubkey(pubkey_bin, sizeof(pubkey_bin));
  // TODO: Write to results file also
  return;

tweak_failed:
  printf("FATAL: Unable to generate public key that matches the pattern. "
         "Please try "
         "again from step2.\n");
  exit(1);
}

int main(int argc, char** argv) {
  int opt, opt_idx;
  char* input_keys = NULL;
  char* pattern = NULL;
  bool step1 = false, key = false, step3 = false, help = false, verbose = false,
       generate = false, combine = false, convert = false;

  fprintf(stderr,
          NAME " v" VERSION "\n"
               "One half of noclvag.\n"
               "\n"
               "noclvag, Nostr OpenCL Vanity Address Generator.\n"
               "Copyright (C) 2024 alex0jsan <nostr:npub1alex0jsan7wt5aq7exv9je9qlvdwm69sr7u6m8msjr77xv6yj60qkp8462>\n"
               "\n"
               "        !!! WARNING WARNING WARNING !!!\n"
               "  noclvag is experimental software. It hasn't\n"
               "  been audited and might produce weak keys \n"
               "  that might be easily compromised.\n"
               "\n"
               "  Use at your own risk.\n"
               "\n");

  if (argc <= 1) {
    op_usage(argv[0]);
    return 1;
  }

  struct option long_opts[] = {{"step1", required_argument, NULL, '1'},
                               {"key", required_argument, NULL, 'k'},
                               {"step3", no_argument, NULL, '3'},
                               {"generate-key", no_argument, NULL, 'g'},
                               {"convert-key", required_argument, NULL, 'c'},
                               {"combine-keys", required_argument, NULL, 'C'},
                               {"verbose", no_argument, NULL, 'v'},
                               {"help", no_argument, NULL, 'h'},
                               {0, 0, 0, 0}};

  /* Stop getopt_long from printing error messages */
  opterr = 0;

  while ((opt = getopt_long(argc, argv, "1:k:3gc:C:vh", long_opts, &opt_idx)) !=
         -1) {
    switch (opt) {
    case '1':
      step1 = true;
      pattern = optarg;
      break;
    case 'k':
      key = true;
      input_keys = optarg;
      break;
    case '3':
      step3 = true;
      break;
    case 'g':
      generate = true;
      break;
    case 'c':
      convert = true;
      input_keys = optarg;
      break;
    case 'C':
      combine = true;
      input_keys = optarg;
      break;
    case 'v':
      verbose = true;
      break;
    case 'h':
      help = true;
      break;
      /* Unknown option */
    case '?':
      /* Option missing required argument */
    case ':':
    default:
      fprintf(stderr, "FATAL: Invalid or missing arguments.\n");
      return 1;
    }
  }

  if (help) {
    op_help(argv[0]);
  } else if (step1) {
    if (!key) {
      input_keys = NULL;
    }
    op_step1(pattern, input_keys, verbose);
  } else if (step3) {
    op_step3(verbose);
  } else if (generate) {
    op_generate_keypair();
  } else if (convert) {
    op_convert_key(input_keys);
  } else if (combine) {
    op_combine_keys(input_keys, verbose);
  } else {
    op_usage(argv[0]);
  }

  return 0;
}
