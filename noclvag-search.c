/*
 * noclvag, Nostr OpenCL Vanity Address Generator.
 * Copyright (C) 2024 alex0jsan <npub1alex0jsan7wt5aq7exv9je9qlvdwm69sr7u6m8msjr77xv6yj60qkp8462>
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

#include <assert.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <openssl/rand.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "globals.h"
#include "oclengine.h"
#include "pattern.h"
#include "util-openssl.h"
#include "util.h"

/* Don't build with very old OpenSSL versions */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error                                                                         \
    "OpenSSL version is lower than 1.1.1. Please build with a more recent OpenSSL version."
#endif

#define NAME "noclvag-search"
#define VERSION "0.1"

#define MAX_DEVS 32

struct options_s {
  bool op_step2;
  bool op_list_devices;
  bool op_help;
  int8_t platformidx;
  int8_t deviceidx;
  uint8_t verbose;
  char* seedfile;
  uint32_t nthreads;
  uint32_t worksize;
  uint32_t nrows;
  uint32_t ncols;
  uint32_t invsize;
  bool verify_mode;
  bool safe_mode;
  char* devstrs[MAX_DEVS];
  uint8_t ndevstrs;
};

static void op_usage(const char* name) {
  fprintf(
      stderr,
      "Usage: %s [OPTIONS] --step2\n"
      "       %s -l\n"
      "       %s -h\n"
      "\n"
      "Operations:\n"
      "  -2, --step2   Search for a secret key to match a noclvag-tool request "
      "file.\n"
      "\n"
      "  -l, --list-devices\n"
      "                List OpenCL platforms and devices.\n"
      "\n"
      "  -h, --help    Print more help text.\n"
      "\n"
      "Options:\n"
      "  -v, --verbose\n"
      "                Produce more verbose output.\n"
      "\n"
      "  -q, --quiet\n"
      "                Produce less verbose output.\n"
      "\n"
      "  -p, --platform PLATFORM\n"
      "                Select OpenCL platform.\n"
      "\n"
      "  -d, --device DEVICE\n"
      "                Select OpenCL device.\n"
      "\n"
      "Advanced options:\n"
      "  -D, --device-string DEVSTR\n"
      "                Use OpenCL device, identified by device string.\n"
      "                Format: PLATFORM:DEVICE[,DEVOPTS...]\n"
      "                Example: 0:0,grid=1024x1024,threads=256,invsize=32\n"
      "\n"
      "  -S, --safe-mode\n"
      "                Safe mode; Disable OpenCL loop unrolling "
      "optimizations.\n"
      "\n"
      "  -V, --verify\n"
      "                Enable kernel/OpenCL/hardware verification (very "
      "slow).\n"
      "\n"
      "  -w, --work-size WORKSIZE\n"
      "                Set work items per thread in a work unit.\n"
      "\n"
      "  -t, --threads THREADS\n"
      "                Set target thread count per multiprocessor.\n"
      "\n"
      "  -g, --grid-size GRIDSIZE\n"
      "                Set grid size. Example: 1024x1024\n"
      "\n"
      "  -i, --inverse-size INVSIZE\n"
      "                Set modular inverse ops per thread.\n"
      "\n"
      "  -s, --seed-file FILE\n"
      "                Seed random number generator from file.\n"
      "\n",
      name, name, name);
}

static void op_help(char* name) {
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
      "  To generate a Nostr vanity address, follow the instructions in\n"
      "  noclvag-tool's help to acquire a request file.\n"
      "\n"
      "  Copy the generated request file (\"./%s\" by default) here and\n"
      "  run the --step2 operation of this tool. For example, you can:\n"
      "    %s -p 0 -d 0 --step2\n"
      "\n"
      "  Be sure to adjust the parameters to use your fastest OpenCL device. "
      "Usually\n"
      "  a GPU.\n"
      "\n"
      "  Once the key is found, copy back the response file\n"
      "  (\"./%s\" by default) and follow the rest of the instructions\n"
      "  in noclvag-tool's help.\n"
      "\n"
      "  And finally, be sure to securely purge the files.\n"
      "\n"
      "OpenCL Platform and Device Selection:\n"
      "  By default, if no device is specified, and the system has exactly one "
      "OpenCL\n"
      "  device, it will be selected automatically. Otherwise if the system "
      "has\n"
      "  multiple OpenCL devices and no device is specified, an error will be\n"
      "  reported.\n"
      "\n"
      "  To use multiple devices simultaneously, specify the -D option for "
      "each\n"
      "  device.\n"
      "\n"
      "Enjoy, and stay free.\n"
      "\n",
      NOCLVAG_REQUEST_FILENAME, name, NOCLVAG_RESPONSE_FILENAME);
}

static void noclvag_get_request_row(const char* filename,
                                    noclvag_request_row* row_ptr) {
  FILE* file_ptr;
  size_t len;

  if (filename == NULL) {
    filename = NOCLVAG_REQUEST_FILENAME;
  }
  file_ptr = fopen(filename, "rb");

  /* Read pattern */
  row_ptr->pattern_len = NOCLVAG_PATTERN_MAX_LEN;
  if (noclvag_get_hex_col(file_ptr, row_ptr->pattern, &row_ptr->pattern_len)) {
    fprintf(stderr,
            "FATAL: Incorrect request file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read pattern mask */
  len = row_ptr->pattern_len;
  if (noclvag_get_hex_col(file_ptr, row_ptr->pattern_mask, &len)) {
    fprintf(stderr,
            "FATAL: Incorrect request file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  if (len != row_ptr->pattern_len) {
    fprintf(stderr,
            "FATAL: Incorrect request file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /* Read compressed pubkey1 */
  len = NOCLVAG_CPUBKEY_LEN;
  if (noclvag_get_hex_col(file_ptr, row_ptr->cpubkey1, &len)) {
    fprintf(stderr,
            "FATAL: Incorrect request file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  if (len != NOCLVAG_CPUBKEY_LEN) {
    fprintf(stderr,
            "FATAL: Incorrect request file format. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  fclose(file_ptr);
}

int main(int argc, char** argv) {
  struct options_s options = {
      .op_step2 = false,
      .op_list_devices = false,
      .op_help = false,
      .platformidx = -1,
      .deviceidx = -1,
      .verbose = 1,
      .seedfile = NULL,
      .nthreads = 0,
      .worksize = 0,
      .nrows = 0,
      .ncols = 0,
      .invsize = 0,
      .verify_mode = false,
      .safe_mode = false,
      .ndevstrs = 0,
  };

  int opt, opt_idx;
  char* pend;
  int opened = 0;

  noclvag_context_t* vcp = NULL;
  noclvag_ocl_context_t* vocp = NULL;

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

  struct option long_opts[] = {{"step2", no_argument, NULL, '2'},
                               {"list-devices", no_argument, NULL, 'l'},
                               {"help", no_argument, NULL, 'h'},
                               {"verbose", no_argument, NULL, 'v'},
                               {"quiet", no_argument, NULL, 'q'},
                               {"platform", required_argument, NULL, 'p'},
                               {"device", required_argument, NULL, 'd'},
                               {"device-string", required_argument, NULL, 'D'},
                               {"safe-mode", no_argument, NULL, 'S'},
                               {"verify", no_argument, NULL, 'V'},
                               {"work-size", required_argument, NULL, 'w'},
                               {"threads", required_argument, NULL, 't'},
                               {"grid-size", required_argument, NULL, 'g'},
                               {"inverse-size", required_argument, NULL, 'i'},
                               {"seed-file", required_argument, NULL, 's'},
                               {0, 0, 0, 0}};

  /* Stop getopt_long from printing error messages */
  opterr = 0;

  while ((opt = getopt_long(argc, argv, "2lhvqp:d:D:SVw:t:g:i:s:", long_opts,
                            &opt_idx)) != -1) {
    switch (opt) {
    case '2':
      options.op_step2 = true;
      break;
    case 'l':
      options.op_list_devices = true;
      break;
    case 'h':
      options.op_help = true;
      break;
    case 'v':
      options.verbose = 2;
      break;
    case 'q':
      options.verbose = 0;
      break;
    case 'p':
      options.platformidx = atoi(optarg);
      break;
    case 'd':
      options.deviceidx = atoi(optarg);
      break;
    case 'D':
      if (options.ndevstrs >= MAX_DEVS) {
        fprintf(stderr, "FATAL: Too many OpenCL devices (limit %d).\n",
                MAX_DEVS);
        return 1;
      }
      options.devstrs[options.ndevstrs] = optarg;
      options.ndevstrs++;
      break;
    case 'S':
      options.safe_mode = true;
      break;
    case 'V':
      options.verify_mode = true;
      break;
    case 'w':
      options.worksize = atoi(optarg);
      if (options.worksize <= 0) {
        fprintf(stderr, "FATAL: Invalid work size \"%s\".\n", optarg);
        return 1;
      }
      break;
    case 't':
      options.nthreads = atoi(optarg);
      if (options.nthreads <= 0) {
        fprintf(stderr, "FATAL: Invalid thread count \"%s\".\n", optarg);
        return 1;
      }
      break;
    case 'g':
      options.nrows = 0;
      options.ncols = strtol(optarg, &pend, 0);
      if (pend && *pend == 'x') {
        options.nrows = strtol(pend + 1, NULL, 0);
      }
      if (!options.nrows || !options.ncols) {
        fprintf(stderr, "FATAL: Invalid grid size \"%s\".\n", optarg);
        return 1;
      }
      break;
    case 'i':
      options.invsize = atoi(optarg);
      if (options.invsize <= 0) {
        fprintf(stderr, "FATAL: Invalid modular inverse size \"%s\".\n",
                optarg);
        return 1;
      }
      if (options.invsize & (options.invsize - 1)) {
        fprintf(stderr,
                "FATAL: Modular inverse size must be "
                "a power of 2. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        return 1;
      }
      break;
    case 's':
      if (options.seedfile != NULL) {
        fprintf(stderr,
                "FATAL: Multiple RNG seeds specified. (Debug info:%s:%d)\n",
                __FILE__, __LINE__);
        return 1;
      }
      options.seedfile = optarg;
      break;
    case '?':
      /* Unknown option */
    case ':':
      /* Option missing required argument */
    default:
      fprintf(stderr,
              "FATAL: Invalid or missing arguments. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      return 1;
    }
  }

  if (options.op_help) {
    op_help(argv[0]);
    return 0;
  }

  else if (options.op_list_devices) {
    noclvag_ocl_enumerate_devices();
    return 0;
  }

  else if (options.op_step2) {
    if (options.seedfile) {
      opt = -1;

      struct stat st;
      if (!stat(options.seedfile, &st) && (st.st_mode & (S_IFBLK | S_IFCHR))) {
        opt = 32;
      }

      opt = RAND_load_file(options.seedfile, opt);
      if (!opt) {
        fprintf(stderr, "FATAL: Could not load RNG seed \"%s\".\n", optarg);
        return 1;
      }
      if (options.verbose > 0) {
        fprintf(stderr, "INFO: Read %d bytes from RNG seed file.\n", opt);
      }
    }

    /*** Get pattern details and public key 1 from file ***/
    noclvag_request_row reqrow;
    noclvag_get_request_row(NULL, &reqrow);

    /*** Validate public key ***/
    /* Before we can call actual API functions, we need to create a "context".
     */
    unsigned char randomize[32];
    secp256k1_context* ctx_ptr =
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
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

    /** Parse a variable-length public key into the pubkey object.
     *  Returns: 1 if the public key was fully valid.
     *           0 if the public key could not be parsed or is invalid. */
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx_ptr, &pubkey, reqrow.cpubkey1,
                                   sizeof(reqrow.cpubkey1))) {
      fprintf(stderr,
              "FATAL: Invalid base public key. Probably a corrupt request "
              "file. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      return 1;
    }

    vcp = noclvag_context_new();

    vcp->vc_verbose = options.verbose;

    /* Validate pattern length */
    /* Public key is 32-bytes */
    if ((reqrow.pattern_len < 1) || (reqrow.pattern_len > 32)) {
      fprintf(stderr,
              "FATAL: Invalid pattern. Probably a corrupt request file. (Debug "
              "info:%s:%d)\n",
              __FILE__, __LINE__);
      return 1;
    }

    if (!noclvag_context_add_pattern(vcp, reqrow.pattern, reqrow.pattern_mask,
                                     reqrow.pattern_len)) {
      fprintf(stderr,
              "FATAL: Invalid pattern. Probably a corrupt request file. (Debug "
              "info:%s:%d)\n",
              __FILE__, __LINE__);
      return 1;
    }

    if (!vcp->vc_npatterns) {
      fprintf(stderr,
              "FATAL: No patterns to search for. Probably a corrupt "
              "request file. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      return 1;
    }

    /* Validate base public key */
    EC_GROUP* pgroup = EC_GROUP_new_by_curve_name(NID_secp256k1);
    vcp->vc_pubkey_base = EC_POINT_new(pgroup);
    if (!EC_POINT_oct2point(pgroup, vcp->vc_pubkey_base, reqrow.cpubkey1,
                            sizeof(reqrow.cpubkey1), NULL)) {
      fprintf(stderr,
              "FATAL: Invalid base public key. Probably a corrupt request "
              "file. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      return 1;
    }
    EC_GROUP_free(pgroup);

    if (options.ndevstrs) {
      for (opt = 0; opt < options.ndevstrs; opt++) {
        vocp = noclvag_ocl_context_new_from_devstr(
            vcp, options.devstrs[opt], options.safe_mode, options.verify_mode);
        if (!vocp) {
          fprintf(stderr, "ERROR: Could not open device \"%s\". Ignoring.\n",
                  options.devstrs[opt]);
        } else {
          opened++;
        }
      }
    } else {
      vocp = noclvag_ocl_context_new(
          vcp, options.platformidx, options.deviceidx, options.safe_mode,
          options.verify_mode, options.worksize, options.nthreads,
          options.nrows, options.ncols, options.invsize);
      if (vocp) {
        opened++;
      }
    }

    if (!opened) {
      fprintf(stderr,
              "FATAL: Could not open any OpenCL device. (Debug info:%s:%d)\n",
              __FILE__, __LINE__);
      return 1;
    }

    if (options.verbose > 1) {
      noclvag_ocl_enumerate_devices();
    }

    opt = noclvag_context_start_threads(vcp);
    if (opt) {
      return 1;
    }

    noclvag_context_wait_for_completion(vcp);
    noclvag_ocl_context_free(vocp);

    return 0;
  } else {
    op_usage(argv[0]);
  }

  return 0;
}
