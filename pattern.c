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

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <pthread.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "avl.h"
#include "oclengine.h"
#include "pattern.h"
#include "util-openssl.h"
#include "util.h"

static void noclvag_pattern_range_sum(noclvag_pattern_t* vp, BIGNUM* result,
                                      BIGNUM* tmp1);
static int noclvag_addr_sort(noclvag_context_t* vcp, void* buf);
static void noclvag_pattern_context_clear_all_patterns(noclvag_context_t* vcp);
static int get_pattern_ranges(const uint8_t* pattern,
                              const uint8_t* pattern_mask,
                              const size_t pattern_len, BIGNUM** result);
static noclvag_pattern_t*
noclvag_pattern_add_ranges(avl_root_t* rootp, const uint8_t* pattern,
                           const uint8_t* pattern_mask,
                           const size_t pattern_len, BIGNUM** ranges);

/*
 * Common code for execution helper
 */

EC_KEY* noclvag_exec_context_new_key(void) {
  return EC_KEY_new_by_curve_name(NID_secp256k1);
}

/*
 * Thread synchronization helpers
 */

static pthread_mutex_t noclvag_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t noclvag_thread_rdcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t noclvag_thread_wrcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t noclvag_thread_upcond = PTHREAD_COND_INITIALIZER;

static void __noclvag_exec_context_yield(noclvag_exec_context_t* vxcp) {
  vxcp->vxc_lockmode = 0;
  while (vxcp->vxc_vc->vc_thread_excl) {
    if (vxcp->vxc_stop) {
      assert(vxcp->vxc_vc->vc_thread_excl);
      vxcp->vxc_stop = 0;
      pthread_cond_signal(&noclvag_thread_upcond);
    }
    pthread_cond_wait(&noclvag_thread_rdcond, &noclvag_thread_lock);
  }
  assert(!vxcp->vxc_stop);
  assert(!vxcp->vxc_lockmode);
  vxcp->vxc_lockmode = 1;
}

int noclvag_exec_context_upgrade_lock(noclvag_exec_context_t* vxcp) {
  noclvag_exec_context_t* tp;
  noclvag_context_t* vcp;

  if (vxcp->vxc_lockmode == 2) {
    return 0;
  }

  pthread_mutex_lock(&noclvag_thread_lock);

  assert(vxcp->vxc_lockmode == 1);
  vxcp->vxc_lockmode = 0;
  vcp = vxcp->vxc_vc;

  if (vcp->vc_thread_excl++) {
    assert(vxcp->vxc_stop);
    vxcp->vxc_stop = 0;
    pthread_cond_signal(&noclvag_thread_upcond);
    pthread_cond_wait(&noclvag_thread_wrcond, &noclvag_thread_lock);

    for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
      assert(!tp->vxc_lockmode);
      assert(!tp->vxc_stop);
    }
  } else {
    for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
      if (tp->vxc_lockmode) {
        assert(tp->vxc_lockmode != 2);
        tp->vxc_stop = 1;
      }
    }

    do {
      for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
        if (tp->vxc_lockmode) {
          assert(tp->vxc_lockmode != 2);
          pthread_cond_wait(&noclvag_thread_upcond, &noclvag_thread_lock);
          break;
        }
      }
    } while (tp);
  }

  vxcp->vxc_lockmode = 2;
  pthread_mutex_unlock(&noclvag_thread_lock);
  return 1;
}

void noclvag_exec_context_downgrade_lock(noclvag_exec_context_t* vxcp) {
  pthread_mutex_lock(&noclvag_thread_lock);
  assert(vxcp->vxc_lockmode == 2);
  assert(!vxcp->vxc_stop);
  if (!--vxcp->vxc_vc->vc_thread_excl) {
    vxcp->vxc_lockmode = 1;
    pthread_cond_broadcast(&noclvag_thread_rdcond);
    pthread_mutex_unlock(&noclvag_thread_lock);
    return;
  }
  pthread_cond_signal(&noclvag_thread_wrcond);
  __noclvag_exec_context_yield(vxcp);
  pthread_mutex_unlock(&noclvag_thread_lock);
}

int noclvag_exec_context_init(noclvag_context_t* vcp,
                              noclvag_exec_context_t* vxcp) {
  pthread_mutex_lock(&noclvag_thread_lock);

  memset(vxcp, 0, sizeof(*vxcp));

  vxcp->vxc_vc = vcp;

  vxcp->vxc_bntarg = BN_new();
  vxcp->vxc_bntmp = BN_new();
  vxcp->vxc_bntmp2 = BN_new();

  vxcp->vxc_bnctx = BN_CTX_new();
  assert(vxcp->vxc_bnctx);
  vxcp->vxc_key = noclvag_exec_context_new_key();
  assert(vxcp->vxc_key);
  EC_KEY_precompute_mult(vxcp->vxc_key, vxcp->vxc_bnctx);

  vxcp->vxc_lockmode = 0;
  vxcp->vxc_stop = 0;

  vxcp->vxc_next = vcp->vc_threads;
  vcp->vc_threads = vxcp;
  __noclvag_exec_context_yield(vxcp);
  pthread_mutex_unlock(&noclvag_thread_lock);
  return 1;
}

void noclvag_exec_context_del(noclvag_exec_context_t* vxcp) {
  noclvag_exec_context_t *tp, **pprev;

  if (vxcp->vxc_lockmode == 2) {
    noclvag_exec_context_downgrade_lock(vxcp);
  }

  pthread_mutex_lock(&noclvag_thread_lock);
  assert(vxcp->vxc_lockmode == 1);
  vxcp->vxc_lockmode = 0;

  for (pprev = &vxcp->vxc_vc->vc_threads, tp = *pprev;
       (tp != vxcp) && (tp != NULL); pprev = &tp->vxc_next, tp = *pprev)
    ;

  assert(tp == vxcp);
  *pprev = tp->vxc_next;

  if (tp->vxc_stop) {
    pthread_cond_signal(&noclvag_thread_upcond);
  }

  BN_clear_free(vxcp->vxc_bntarg);
  BN_clear_free(vxcp->vxc_bntmp);
  BN_clear_free(vxcp->vxc_bntmp2);
  BN_CTX_free(vxcp->vxc_bnctx);
  vxcp->vxc_bnctx = NULL;
  pthread_mutex_unlock(&noclvag_thread_lock);
}

void noclvag_exec_context_yield(noclvag_exec_context_t* vxcp) {
  if (vxcp->vxc_lockmode == 2) {
    noclvag_exec_context_downgrade_lock(vxcp);
  }

  else if (vxcp->vxc_stop) {
    assert(vxcp->vxc_lockmode == 1);
    pthread_mutex_lock(&noclvag_thread_lock);
    __noclvag_exec_context_yield(vxcp);
    pthread_mutex_unlock(&noclvag_thread_lock);
  }

  assert(vxcp->vxc_lockmode == 1);
}

void noclvag_exec_context_consolidate_key(noclvag_exec_context_t* vxcp) {
  if (vxcp->vxc_delta) {
    BN_clear(vxcp->vxc_bntmp);
    BN_set_word(vxcp->vxc_bntmp, vxcp->vxc_delta);
    BN_add(vxcp->vxc_bntmp2, EC_KEY_get0_private_key(vxcp->vxc_key),
           vxcp->vxc_bntmp);
    noclvag_set_privkey(vxcp->vxc_bntmp2, vxcp->vxc_key);
    vxcp->vxc_delta = 0;
  }
}

void noclvag_exec_context_calc_pubkey(noclvag_exec_context_t* vxcp) {
  EC_POINT* pubkey;
  const EC_GROUP* pgroup;
  unsigned char pubkey_buf[NOCLVAG_CPUBKEY_LEN];

  noclvag_exec_context_consolidate_key(vxcp);
  pgroup = EC_KEY_get0_group(vxcp->vxc_key);
  pubkey = EC_POINT_new(pgroup);
  EC_POINT_copy(pubkey, EC_KEY_get0_public_key(vxcp->vxc_key));

  assert(vxcp->vxc_vc->vc_pubkey_base);
  EC_POINT_add(pgroup, pubkey, pubkey, vxcp->vxc_vc->vc_pubkey_base,
               vxcp->vxc_bnctx);

  assert(EC_POINT_point2oct(pgroup, pubkey, POINT_CONVERSION_COMPRESSED,
                            pubkey_buf, sizeof(pubkey_buf),
                            vxcp->vxc_bnctx) == NOCLVAG_CPUBKEY_LEN);

  memcpy(vxcp->vxc_binres, &pubkey_buf[1], NOCLVAG_PUBKEY_LEN);

  EC_POINT_free(pubkey);
}

enum { timing_hist_size = 5 };

typedef struct _timing_info_s {
  struct _timing_info_s* ti_next;
  pthread_t ti_thread;
  unsigned long ti_last_rate;

  unsigned long long ti_hist_time[timing_hist_size];
  unsigned long ti_hist_work[timing_hist_size];
  int ti_hist_last;
} timing_info_t;

static pthread_mutex_t timing_mutex = PTHREAD_MUTEX_INITIALIZER;

int noclvag_output_timing(noclvag_context_t* vcp, int cycle,
                          struct timeval* last) {
  pthread_t me;
  struct timeval tvnow, tv;
  timing_info_t *tip, *mytip;
  unsigned long long rate, myrate = 0, mytime, total, sincelast;
  int p, i;

  /* Compute the rate */
  gettimeofday(&tvnow, NULL);
  timersub(&tvnow, last, &tv);
  memcpy(last, &tvnow, sizeof(*last));
  mytime = tv.tv_usec + (1000000ULL * tv.tv_sec);
  if (!mytime) {
    mytime = 1;
  }
  rate = 0;

  pthread_mutex_lock(&timing_mutex);
  me = pthread_self();
  for (tip = vcp->vc_timing_head, mytip = NULL; tip != NULL;
       tip = tip->ti_next) {
    if (pthread_equal(tip->ti_thread, me)) {
      mytip = tip;
      p = ((tip->ti_hist_last + 1) % timing_hist_size);
      tip->ti_hist_time[p] = mytime;
      tip->ti_hist_work[p] = cycle;
      tip->ti_hist_last = p;

      mytime = 0;
      myrate = 0;
      for (i = 0; i < timing_hist_size; i++) {
        mytime += tip->ti_hist_time[i];
        myrate += tip->ti_hist_work[i];
      }
      myrate = (myrate * 1000000) / mytime;
      tip->ti_last_rate = myrate;
      rate += myrate;
    } else {
      rate += tip->ti_last_rate;
    }
  }
  if (!mytip) {
    mytip = (timing_info_t*)malloc(sizeof(*tip));
    mytip->ti_next = vcp->vc_timing_head;
    mytip->ti_thread = me;
    vcp->vc_timing_head = mytip;
    mytip->ti_hist_last = 0;
    mytip->ti_hist_time[0] = mytime;
    mytip->ti_hist_work[0] = cycle;
    for (i = 1; i < timing_hist_size; i++) {
      mytip->ti_hist_time[i] = 1;
      mytip->ti_hist_work[i] = 0;
    }
    myrate = ((unsigned long long)cycle * 1000000) / mytime;
    mytip->ti_last_rate = myrate;
    rate += myrate;
  }

  vcp->vc_timing_total += cycle;
  if (vcp->vc_timing_prevfound != vcp->vc_found) {
    vcp->vc_timing_prevfound = vcp->vc_found;
    vcp->vc_timing_sincelast = 0;
  }
  vcp->vc_timing_sincelast += cycle;

  if (mytip != vcp->vc_timing_head) {
    pthread_mutex_unlock(&timing_mutex);
    return myrate;
  }
  total = vcp->vc_timing_total;
  sincelast = vcp->vc_timing_sincelast;
  pthread_mutex_unlock(&timing_mutex);

  noclvag_output_timing_console(vcp, sincelast, rate, total);
  return myrate;
}

void noclvag_context_thread_exit(noclvag_context_t* vcp) {
  timing_info_t *tip, **ptip;
  pthread_t me;

  pthread_mutex_lock(&timing_mutex);
  me = pthread_self();
  for (ptip = &vcp->vc_timing_head, tip = *ptip; tip != NULL;
       ptip = &tip->ti_next, tip = *ptip) {
    if (!pthread_equal(tip->ti_thread, me)) {
      continue;
    }
    *ptip = tip->ti_next;
    free(tip);
    break;
  }
  pthread_mutex_unlock(&timing_mutex);
}

static void noclvag_timing_info_free(noclvag_context_t* vcp) {
  timing_info_t* tp;
  while (vcp->vc_timing_head != NULL) {
    tp = vcp->vc_timing_head;
    vcp->vc_timing_head = tp->ti_next;
    free(tp);
  }
}

void noclvag_output_timing_console(noclvag_context_t* vcp, double count,
                                   uint64_t rate, uint64_t total) {
  double prob, time, targ;
  const char* unit;
  char linebuf[80];
  size_t i;
  int rem, p;

  const double targs[] = {0.5, 0.75, 0.8, 0.9, 0.95, 1.0};

  targ = rate;
  unit = "key/s";
  if (targ > 1000) {
    unit = "Kkey/s";
    targ /= 1000.0;
    if (targ > 1000) {
      unit = "Mkey/s";
      targ /= 1000.0;
      if (targ > 1000) {
        unit = "Gkey/s";
        targ /= 1000.0;
      }
    }
  }

  rem = sizeof(linebuf);
  p = snprintf(linebuf, rem, "[%.2f %s][total %lu]", targ, unit, total);
  assert(p > 0);
  rem -= p;
  if (rem < 0) {
    rem = 0;
  }

  if (vcp->vc_chance >= 1.0) {
    prob = 1.0f - exp(-count / vcp->vc_chance);

    if (prob <= 0.999) {
      p = snprintf(&linebuf[p], rem, "[Prob %.1f%%]", prob * 100);
      assert(p > 0);
      rem -= p;
      if (rem < 0) {
        rem = 0;
      }
      p = sizeof(linebuf) - rem;
    }

    for (i = 0; i < sizeof(targs) / sizeof(targs[0]); i++) {
      targ = targs[i];
      if ((targ < 1.0) && (prob <= targ)) {
        break;
      }
    }

    if (targ < 1.0) {
      time = ((-vcp->vc_chance * log(1.0 - targ)) - count) / rate;
      unit = "s";
      if (time > 60) {
        time /= 60;
        unit = "min";
        if (time > 60) {
          time /= 60;
          unit = "h";
          if (time > 24) {
            time /= 24;
            unit = "d";
            if (time > 365) {
              time /= 365;
              unit = "y";
            }
          }
        }
      }

      if (time > 1000000) {
        p = snprintf(&linebuf[p], rem, "[%d%% in %e%s]", (int)(100 * targ),
                     time, unit);
      } else {
        p = snprintf(&linebuf[p], rem, "[%d%% in %.1f%s]", (int)(100 * targ),
                     time, unit);
      }
      assert(p > 0);
      rem -= p;
      if (rem < 0) {
        rem = 0;
      }
      p = sizeof(linebuf) - rem;
    }
  }

  if (vcp->vc_found) {
    {
      p = snprintf(&linebuf[p], rem, "[Found %lu/%lu]", vcp->vc_found,
                   vcp->vc_npatterns_start);
    }
    assert(p > 0);
    rem -= p;
    if (rem < 0) {
      rem = 0;
    }
  }

  if (rem) {
    memset(&linebuf[sizeof(linebuf) - rem], 0x20, rem);
    linebuf[sizeof(linebuf) - 1] = '\0';
  }
  fprintf(stderr, "\r%s", linebuf);
  // fflush(stdout);
}

void noclvag_output_match(noclvag_context_t* vcp, EC_KEY* pkey,
                          const uint8_t* pattern, const uint8_t* pattern_mask,
                          const size_t pattern_len) {
  unsigned char seckey2_bin[NOCLVAG_SECKEY_LEN];
  unsigned char pubkey2_bin[NOCLVAG_PUBKEY_LEN];
  unsigned char pubkey3_bin[NOCLVAG_PUBKEY_LEN];
  unsigned char cpubkey1_bin[NOCLVAG_CPUBKEY_LEN];
  unsigned char randomize[32];
  secp256k1_xonly_pubkey xonly_pubkey2;
  secp256k1_xonly_pubkey xonly_pubkey3;
  secp256k1_keypair keypair2;
  secp256k1_pubkey pubkey2;
  secp256k1_pubkey pubkey1;

  /* Convert secret key 2 and public key 1 to binary */
  {
    assert(EC_KEY_priv2oct(pkey, seckey2_bin, sizeof(seckey2_bin)) > 1);

    const EC_GROUP* pgroup;
    pgroup = EC_KEY_get0_group(pkey);
    assert(EC_POINT_point2oct(pgroup, vcp->vc_pubkey_base,
                              POINT_CONVERSION_COMPRESSED, cpubkey1_bin,
                              sizeof(cpubkey1_bin),
                              NULL) == NOCLVAG_CPUBKEY_LEN);
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
  if (secp256k1_keypair_create(ctx, &keypair2, seckey2_bin) != 1) {
    /*  Returns: 1: secret was valid, keypair is ready to use */
    fprintf(stderr,
            "FATAL: Second private key is invalid. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  if (vcp->vc_verbose > 1) {
    fprintf(stderr, "INFO: Second private key : ");
    fprinthex(stderr, seckey2_bin, sizeof(seckey2_bin));
    fprintf(stderr, "\n");
  }

  /* Before tweaking */
  if (vcp->vc_verbose > 1) {
    fprintf(stderr, "INFO: Public key before tweaking: ");

    /* Generate X-coordinate only public key */
    /* Returns: 1 always. */
    assert(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey2, NULL, &keypair2) ==
           1);

    /* Serialize X-only public key to binary */
    /* Returns: 1 always. */
    assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey2_bin, &xonly_pubkey2) ==
           1);

    fprinthex(stderr, pubkey2_bin, sizeof(pubkey2_bin));
    fprintf(stderr, "\n");
  }

  /* After tweaking */

  /** Get the public key from a keypair.
   *  Returns: 1 always.
   */
  assert(secp256k1_keypair_pub(ctx, &pubkey2, &keypair2) == 1);

  /** Parse a variable-length public key into the pubkey object.
   *  Returns: 1 if the public key was fully valid.
   *           0 if the public key could not be parsed or is invalid.
   */
  if (!secp256k1_ec_pubkey_parse(ctx, &pubkey1, cpubkey1_bin,
                                 sizeof(cpubkey1_bin))) {
    fprintf(stderr, "FATAL: Public key 1 is invalid. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /** Tweak a public key by adding tweak times the generator to it.
   *  Returns: 0 if the arguments are invalid or the resulting public key would
   * be invalid (only when the tweak is the negation of the corresponding secret
   * key). 1 otherwise.
   */
  /* The tweak is the secret key we found */
  if (!secp256k1_ec_pubkey_tweak_add(ctx, &pubkey1, seckey2_bin)) {
    fprintf(stderr,
            "FATAL: Resulting public key is invalid. (Debug info:%s:%d)\n",
            __FILE__, __LINE__);
    exit(1);
  }

  /** Converts a secp256k1_pubkey into a secp256k1_xonly_pubkey.
   *  Returns: 1 always.
   */
  assert(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey3, NULL,
                                            &pubkey1) == 1);

  /* Serialize X-only public key to binary */
  /* Returns: 1 always. */
  assert(secp256k1_xonly_pubkey_serialize(ctx, pubkey3_bin, &xonly_pubkey3) ==
         1);

  if (vcp->vc_verbose > 1) {
    fprintf(stderr, "INFO: Public key after tweaking: ");
    fprinthex(stderr, pubkey3_bin, sizeof(pubkey3_bin));
    fprintf(stderr, "\n");
  }

  noclvag_response_row resrow;

  memcpy(resrow.pattern, pattern, pattern_len);
  memcpy(resrow.pattern_mask, pattern_mask, pattern_len);
  resrow.pattern_len = pattern_len;
  memcpy(resrow.cpubkey1, cpubkey1_bin, sizeof(resrow.cpubkey1));
  memcpy(resrow.seckey2, seckey2_bin, sizeof(resrow.seckey2));

  /* Write output to response file */
  noclvag_put_response_row(NULL, &resrow);

  fprintf(stderr,
          "\n\n"
          "INFO: Key matching pattern found and written to response file.\n"
          "INFO: Copy back the response file and follow the rest of the\n"
          "INFO: instructions in noclvag-tool's help.\n");
}

void noclvag_context_free(noclvag_context_t* vcp) {
  noclvag_timing_info_free(vcp);
  noclvag_pattern_context_clear_all_patterns(vcp);
  BN_clear_free(vcp->vcp_difficulty);
  free(vcp);
}

static void noclvag_pattern_context_next_difficulty(noclvag_context_t* vcp,
                                                    BIGNUM* bntmp,
                                                    BIGNUM* bntmp2,
                                                    BN_CTX* bnctx) {
  char* dbuf;
  size_t address_bit_len = 256;

  BN_clear(bntmp);
  BN_set_bit(bntmp, address_bit_len);
  BN_div(bntmp2, NULL, bntmp, vcp->vcp_difficulty, bnctx);

  dbuf = BN_bn2dec(bntmp2);
  if (vcp->vc_verbose > 0) {
    if (vcp->vc_npatterns > 1) {
      fprintf(stderr, "Next match difficulty: %s (%ld patterns)\n", dbuf,
              vcp->vc_npatterns);
    } else {
      fprintf(stderr, "Difficulty: %s\n", dbuf);
    }
  }
  vcp->vc_chance = atof(dbuf);
  OPENSSL_free(dbuf);
}

int noclvag_context_add_pattern(noclvag_context_t* vcp, const uint8_t* pattern,
                                const uint8_t* pattern_mask,
                                const size_t pattern_len) {
  vcp->vc_pattern_generation++;

  noclvag_pattern_t* vp;
  BN_CTX* bnctx;
  BIGNUM *bntmp, *bntmp2, *bntmp3;
  BIGNUM* ranges[2];
  unsigned long npfx;
  char* dbuf;
  const size_t pubkey_nbits = 256;
  int ret = 0;

  bnctx = BN_CTX_new();
  bntmp = BN_new();
  bntmp2 = BN_new();
  bntmp3 = BN_new();

  npfx = 0;
  vp = NULL;
  ret = get_pattern_ranges(pattern, pattern_mask, pattern_len, ranges);
  if (!ret) {
    vp = noclvag_pattern_add_ranges(&vcp->vcp_avlroot, pattern, pattern_mask,
                                    pattern_len, ranges);
  }

  if (ret == -2) {
    fprintf(stderr, "ERROR: Pattern not possible: ");
    fprinthex(stderr, pattern, pattern_len);
    fprintf(stderr, "\n");
  }

  if (vp) {
    npfx++;
  }

  /* Determine the probability of finding a match */
  noclvag_pattern_range_sum(vp, bntmp, bntmp2);
  BN_add(bntmp2, vcp->vcp_difficulty, bntmp);
  BN_copy(vcp->vcp_difficulty, bntmp2);

  if (vcp->vc_verbose > 1) {
    BN_clear(bntmp2);
    BN_set_bit(bntmp2, pubkey_nbits);
    BN_div(bntmp3, NULL, bntmp2, bntmp, bnctx);

    dbuf = BN_bn2dec(bntmp3);
    fprintf(stderr, "Pattern difficulty: %20s \"", dbuf);
    fprinthex(stderr, pattern, pattern_len);
    fprintf(stderr, "\".\n");
    OPENSSL_free(dbuf);
  }

  vcp->vc_npatterns += npfx;
  vcp->vc_npatterns_start += npfx;

  if (npfx) {
    noclvag_pattern_context_next_difficulty(vcp, bntmp, bntmp2, bnctx);
  }

  ret = (npfx != 0);

  BN_clear_free(bntmp);
  BN_clear_free(bntmp2);
  BN_clear_free(bntmp3);
  BN_CTX_free(bnctx);
  return ret;
}

void noclvag_context_clear_all_patterns(noclvag_context_t* vcp) {
  noclvag_pattern_context_clear_all_patterns(vcp);
  vcp->vc_pattern_generation++;
}

int noclvag_context_addr_sort(noclvag_context_t* vcp, void* buf) {
  return noclvag_addr_sort(vcp, buf);
}

int noclvag_context_start_threads(noclvag_context_t* vcp) {
  noclvag_exec_context_t* vxcp;
  int res;

  for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
    res = pthread_create((pthread_t*)&vxcp->vxc_pthread, NULL,
                         (void* (*)(void*)) & noclvag_opencl_loop, vxcp);
    if (res) {
      fprintf(stderr, "ERROR: Could not create thread: %d.\n", res);
      noclvag_context_stop_threads(vcp);
      return -1;
    }
    if (vcp->vc_verbose > 0) {
      fprintf(stderr, "INFO: Thread created.\n");
    }
    vxcp->vxc_thread_active = 1;
  }
  return 0;
}

void noclvag_context_stop_threads(noclvag_context_t* vcp) {
  vcp->vc_halt = true;
  noclvag_context_wait_for_completion(vcp);
  vcp->vc_halt = false;
}

void noclvag_context_wait_for_completion(noclvag_context_t* vcp) {
  noclvag_exec_context_t* vxcp;

  for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
    if (!vxcp->vxc_thread_active) {
      continue;
    }
    pthread_join((pthread_t)vxcp->vxc_pthread, NULL);
    vxcp->vxc_thread_active = 0;
  }
}

/*
 * Find the BIGNUM ranges that produce a given prefix.
 *
 * pfx (hex) = "0xAA", then:
 *  result[0] = AA00000000000000000000000000000000000000000000000000000000000000
 *  result[1] = AAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
 */
static int get_pattern_ranges(const uint8_t* pattern,
                              const uint8_t* pattern_mask,
                              const size_t pattern_len, BIGNUM** result) {
  BIGNUM *bnhigh = NULL, *bnlow = NULL;

  // Public key is 32-bytes
  uint8_t upbin[32], lowbin[32];

  // Initialize to upper (0xFF..) and lower bound (0x00..)
  memset(lowbin, 0x00, sizeof(lowbin));
  memset(upbin, 0xff, sizeof(upbin));

  /* Validate length */
  if ((pattern_len < 1) || (pattern_len > 32)) {
    fprintf(stderr, "WARNING: Ignoring invalid pattern: ");
    fprinthex(stderr, pattern, pattern_len);
    fprintf(stderr, "\n");
    return -1;
  }

  /* Copy pattern bits using mask */
  for (size_t i = 0; i < pattern_len; i++) {
    upbin[i] = pattern[i] | ((~pattern_mask[i]) & 0xff);
    lowbin[i] = pattern[i] & pattern_mask[i];
  }

  bnlow = BN_new();
  bnhigh = BN_new();
  BN_bin2bn(lowbin, sizeof(lowbin), bnlow);
  BN_bin2bn(upbin, sizeof(upbin), bnhigh);

  // bnlow = 1200000000000000000000000000000000000000000000000000000000000000 if
  // pfx = 0x12
  result[0] = bnlow;
  // bnhigh = 12FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
  // if pfx = 0x12
  result[1] = bnhigh;

  return 0;
}

/*
 * Address prefix AVL tree node
 */

const int vpk_nwords = (25 + sizeof(BN_ULONG) - 1) / sizeof(BN_ULONG);

struct _noclvag_pattern_s {
  const uint8_t* vp_pattern;
  const uint8_t* vp_pattern_mask;
  size_t vp_pattern_len;
  avl_item_t vp_item;
  struct _noclvag_pattern_s* vp_sibling;
  BIGNUM* vp_low;
  BIGNUM* vp_high;
};

static void noclvag_pattern_free(noclvag_pattern_t* vp) {
  if (vp->vp_low) {
    BN_free(vp->vp_low);
  }
  if (vp->vp_high) {
    BN_free(vp->vp_high);
  }
  free(vp);
}

static noclvag_pattern_t* noclvag_pattern_avl_search(avl_root_t* rootp,
                                                     BIGNUM* targ) {
  noclvag_pattern_t* vp;
  avl_item_t* itemp = rootp->ar_root;

  while (itemp) {
    vp = avl_item_entry(itemp, noclvag_pattern_t, vp_item);
    if (BN_cmp(vp->vp_low, targ) > 0) {
      itemp = itemp->ai_left;
    } else {
      if (BN_cmp(vp->vp_high, targ) < 0) {
        itemp = itemp->ai_right;
      } else {
        return vp;
      }
    }
  }

  return NULL;
}

static noclvag_pattern_t* noclvag_pattern_avl_insert(avl_root_t* rootp,
                                                     noclvag_pattern_t* vpnew) {
  noclvag_pattern_t* vp;
  avl_item_t* itemp = NULL;
  avl_item_t** ptrp = &rootp->ar_root;
  while (*ptrp) {
    itemp = *ptrp;
    vp = avl_item_entry(itemp, noclvag_pattern_t, vp_item);
    if (BN_cmp(vp->vp_low, vpnew->vp_high) > 0) {
      ptrp = &itemp->ai_left;
    } else {
      if (BN_cmp(vp->vp_high, vpnew->vp_low) < 0) {
        ptrp = &itemp->ai_right;
      } else {
        return vp;
      }
    }
  }
  vpnew->vp_item.ai_up = itemp;
  itemp = &vpnew->vp_item;
  *ptrp = itemp;
  avl_insert_fix(rootp, itemp);
  return NULL;
}

static noclvag_pattern_t* noclvag_pattern_first(avl_root_t* rootp) {
  avl_item_t* itemp;
  itemp = avl_first(rootp);
  if (itemp) {
    return avl_item_entry(itemp, noclvag_pattern_t, vp_item);
  }
  return NULL;
}

static noclvag_pattern_t* noclvag_pattern_next(noclvag_pattern_t* vp) {
  avl_item_t* itemp = &vp->vp_item;
  itemp = avl_next(itemp);
  if (itemp) {
    return avl_item_entry(itemp, noclvag_pattern_t, vp_item);
  }
  return NULL;
}

static noclvag_pattern_t* noclvag_pattern_add(avl_root_t* rootp,
                                              const uint8_t* pattern,
                                              const uint8_t* pattern_mask,
                                              const size_t pattern_len,
                                              BIGNUM* low, BIGNUM* high) {
  noclvag_pattern_t *vp, *vp2;

  assert(BN_cmp(low, high) < 1);
  vp = (noclvag_pattern_t*)malloc(sizeof(*vp));
  if (vp) {
    avl_item_init(&vp->vp_item);
    vp->vp_sibling = NULL;
    vp->vp_pattern = pattern;
    vp->vp_pattern_mask = pattern_mask;
    vp->vp_pattern_len = pattern_len;
    vp->vp_low = low;
    vp->vp_high = high;
    vp2 = noclvag_pattern_avl_insert(rootp, vp);
    if (vp2 != NULL) {
      fprintf(stderr, "WARNING: Pattern ignored: ");
      fprinthex(stderr, pattern, pattern_len);
      fprintf(stderr, "\n");
      fprintf(stderr, "WARNING: Overlaps with:   ");
      fprinthex(stderr, vp2->vp_pattern, vp2->vp_pattern_len);
      fprintf(stderr, "\n");

      noclvag_pattern_free(vp);
      vp = NULL;
    }
  }

  return vp;
}

static void noclvag_pattern_delete(avl_root_t* rootp, noclvag_pattern_t* vp) {
  noclvag_pattern_t *sibp, *delp;

  avl_remove(rootp, &vp->vp_item);
  sibp = vp->vp_sibling;
  while (sibp && sibp != vp) {
    avl_remove(rootp, &sibp->vp_item);
    delp = sibp;
    sibp = sibp->vp_sibling;
    noclvag_pattern_free(delp);
  }
  noclvag_pattern_free(vp);
}

static noclvag_pattern_t*
noclvag_pattern_add_ranges(avl_root_t* rootp, const uint8_t* pattern,
                           const uint8_t* pattern_mask,
                           const size_t pattern_len, BIGNUM** ranges) {
  noclvag_pattern_t* vp;

  assert(ranges[0]);
  vp = noclvag_pattern_add(rootp, pattern, pattern_mask, pattern_len, ranges[0],
                           ranges[1]);
  if (!vp) {
    return NULL;
  }

  return vp;
}

static void noclvag_pattern_range_sum(noclvag_pattern_t* vp, BIGNUM* result,
                                      BIGNUM* tmp1) {
  noclvag_pattern_t* startp;

  startp = vp;
  BN_clear(result);
  do {
    BN_sub(tmp1, vp->vp_high, vp->vp_low);
    BN_add(result, result, tmp1);
    vp = vp->vp_sibling;
  } while (vp && (vp != startp));
}

static void noclvag_pattern_context_clear_all_patterns(noclvag_context_t* vcp) {
  noclvag_pattern_t* vp;
  unsigned long npfx_left = 0;

  while (!avl_root_empty(&vcp->vcp_avlroot)) {
    vp = avl_item_entry(vcp->vcp_avlroot.ar_root, noclvag_pattern_t, vp_item);
    noclvag_pattern_delete(&vcp->vcp_avlroot, vp);
    npfx_left++;
  }

  assert(npfx_left == vcp->vc_npatterns);
  vcp->vc_npatterns = 0;
  vcp->vc_npatterns_start = 0;
  vcp->vc_found = 0;
  BN_clear(vcp->vcp_difficulty);
}

static void noclvag_context_next_difficulty(noclvag_context_t* vcp,
                                            BIGNUM* bntmp, BIGNUM* bntmp2,
                                            BN_CTX* bnctx) {
  char* dbuf;
  size_t address_bit_len = 256;

  BN_clear(bntmp);
  BN_set_bit(bntmp, address_bit_len);
  BN_div(bntmp2, NULL, bntmp, vcp->vcp_difficulty, bnctx);

  dbuf = BN_bn2dec(bntmp2);
  if (vcp->vc_verbose > 0) {
    if (vcp->vc_npatterns > 1) {
      fprintf(stderr, "INFO: Next match difficulty: %s (%u patterns)\n", dbuf,
              vcp->vc_npatterns);
    } else {
      fprintf(stderr, "INFO: Difficulty: %s\n", dbuf);
    }
  }
  vcp->vc_chance = atof(dbuf);
  OPENSSL_free(dbuf);
}

// Return 0 (not found), 1 (found), 2 (not continue)
int noclvag_pattern_test(noclvag_exec_context_t* vxcp) {
  noclvag_context_t* vcp = vxcp->vxc_vc;
  noclvag_pattern_t* vp;
  int res = 0;

  /* Convert public key from binary format (vxcp->vxc_binres) into BIGNUM
  (vxcp->vxc_bntarg) */
  BN_bin2bn(vxcp->vxc_binres, NOCLVAG_PUBKEY_LEN, vxcp->vxc_bntarg);

research:
  vp = noclvag_pattern_avl_search(&vcp->vcp_avlroot, vxcp->vxc_bntarg);
  if (vp) {
    /* Compare pattern using mask against the calculated public key */
    for (size_t i = 0; i < vp->vp_pattern_len; i++) {
      if ((vp->vp_pattern[i] & vp->vp_pattern_mask[i]) !=
          (vxcp->vxc_binres[i] & vp->vp_pattern_mask[i])) {
        if (vcp->vc_verbose > 1) {
          fprintf(stderr, "ERROR: Comparison failed.\n");
          fprintf(stderr, "ERROR: Pattern:    ");
          fprinthex(stderr, vp->vp_pattern, vp->vp_pattern_len);
          fprintf(stderr, "\n");
          fprintf(stderr, "ERROR: Public key: ");
          fprinthex(stderr, vxcp->vxc_binres, NOCLVAG_PUBKEY_LEN);
          fprintf(stderr, "\n");
        }
        vp = NULL;
      }
    }
  }

  if (vp) {
    if (noclvag_exec_context_upgrade_lock(vxcp)) {
      goto research;
    }
    noclvag_exec_context_consolidate_key(vxcp);

    // Output the match information
    noclvag_output_match(vcp, vxcp->vxc_key, vp->vp_pattern,
                         vp->vp_pattern_mask, vp->vp_pattern_len);
    vcp->vc_found++;

    if (1) {
      /* Subtract the range from the difficulty */
      noclvag_pattern_range_sum(vp, vxcp->vxc_bntarg, vxcp->vxc_bntmp);
      BN_sub(vxcp->vxc_bntmp, vcp->vcp_difficulty, vxcp->vxc_bntarg);
      BN_copy(vcp->vcp_difficulty, vxcp->vxc_bntmp);

      noclvag_pattern_delete(&vcp->vcp_avlroot, vp);
      vcp->vc_npatterns--;

      if (!avl_root_empty(&vcp->vcp_avlroot)) {
        noclvag_context_next_difficulty(vcp, vxcp->vxc_bntmp, vxcp->vxc_bntmp2,
                                        vxcp->vxc_bnctx);
      }
      vcp->vc_pattern_generation++;
    }
    res = 1;
  }

  if (avl_root_empty(&vcp->vcp_avlroot)) {
    return 2;
  }

  return res;
}

static int noclvag_addr_sort(noclvag_context_t* vcp, void* buf) {
  noclvag_pattern_t* vp;
  unsigned char* cbuf = (unsigned char*)buf;
  unsigned char bnbuf[64];
  int nbytes, ncopy, npfx = 0;

  /*
   * Walk the prefix tree in order, copy the upper and lower bound
   * values into buf.
   */
  for (vp = noclvag_pattern_first(&vcp->vcp_avlroot); vp != NULL;
       vp = noclvag_pattern_next(vp)) {
    npfx++;
    if (!buf) {
      continue;
    }

    /* Low */
    nbytes = BN_bn2bin(vp->vp_low, bnbuf);
    ncopy = ((nbytes >= 32) ? 32 : ((nbytes > 4) ? (nbytes - 4) : 0));
    memset(cbuf, 0, 32);
    memcpy(cbuf + (32 - ncopy), bnbuf, ncopy);
    cbuf += 32;

    /* High */
    nbytes = BN_bn2bin(vp->vp_high, bnbuf);
    ncopy = ((nbytes >= 32) ? 32 : ((nbytes > 4) ? (nbytes - 4) : 0));
    memset(cbuf, 0, 32);
    memcpy(cbuf + (32 - ncopy), bnbuf, ncopy);
    cbuf += 32;
  }

  return npfx;
}

noclvag_context_t* noclvag_context_new() {
  noclvag_context_t* nctx_ptr = (noclvag_context_t*)malloc(sizeof(*nctx_ptr));
  if (nctx_ptr) {
    memset(nctx_ptr, 0, sizeof(*nctx_ptr));
    nctx_ptr->vc_npatterns = 0;
    nctx_ptr->vc_npatterns_start = 0;
    nctx_ptr->vc_found = 0;
    nctx_ptr->vc_chance = 0.0;

    avl_root_init(&nctx_ptr->vcp_avlroot);
    nctx_ptr->vcp_difficulty = BN_new();
  }

  return nctx_ptr;
}
