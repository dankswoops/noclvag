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

#if !defined(__NOCLVAG_PATTERN_H__)
#define __NOCLVAG_PATTERN_H__ 1

#include "avl.h"
#include "globals.h"

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

typedef struct _noclvag_context_s noclvag_context_t;
typedef struct _noclvag_pattern_s noclvag_pattern_t;
struct _noclvag_exec_context_s;
typedef struct _noclvag_exec_context_s noclvag_exec_context_t;

/* Context of one pattern-matching unit within the process */
struct _noclvag_exec_context_s {
  noclvag_context_t* vxc_vc;
  BN_CTX* vxc_bnctx;
  EC_KEY* vxc_key;
  int vxc_delta;
  unsigned char vxc_binres[32];
  BIGNUM* vxc_bntarg;
  BIGNUM* vxc_bntmp;
  BIGNUM* vxc_bntmp2;

  pthread_t vxc_pthread;
  int vxc_thread_active;

  /* Thread synchronization */
  struct _noclvag_exec_context_s* vxc_next;
  int vxc_lockmode;
  int vxc_stop;
};

/* Application-level context, incl. parameters and global pattern store */
struct _noclvag_context_s {
  uint32_t vc_npatterns;
  uint32_t vc_npatterns_start;
  uint64_t vc_found;
  int vc_pattern_generation;
  double vc_chance;
  uint8_t vc_verbose;
  EC_POINT* vc_pubkey_base;
  bool vc_halt;

  noclvag_exec_context_t* vc_threads;
  int vc_thread_excl;

  /* Performance related members */
  unsigned long long vc_timing_total;
  unsigned long long vc_timing_prevfound;
  unsigned long long vc_timing_sincelast;
  struct _timing_info_s* vc_timing_head;

  avl_root_t vcp_avlroot;
  BIGNUM* vcp_difficulty;
};

/* Context methods */
extern void noclvag_context_free(noclvag_context_t* vcp);
extern int noclvag_context_add_pattern(noclvag_context_t* vcp,
                                       const uint8_t* pattern,
                                       const uint8_t* pattern_mask,
                                       const size_t pattern_len);
extern void noclvag_context_clear_all_patterns(noclvag_context_t* vcp);
extern int noclvag_context_start_threads(noclvag_context_t* vcp);
extern void noclvag_context_stop_threads(noclvag_context_t* vcp);
extern void noclvag_context_wait_for_completion(noclvag_context_t* vcp);

extern noclvag_context_t* noclvag_context_new();
extern int noclvag_pattern_test(noclvag_exec_context_t* vxcp);

/* Utility functions */
extern int noclvag_output_timing(noclvag_context_t* vcp, int cycle,
                                 struct timeval* last);
extern void noclvag_output_match(noclvag_context_t* vcp, EC_KEY* pkey,
                                 const uint8_t* pattern,
                                 const uint8_t* pattern_mask,
                                 const size_t pattern_len);
extern void noclvag_output_timing_console(noclvag_context_t* vcp, double count,
                                          uint64_t rate, uint64_t total);

/* Internal noclvag_context methods */
extern int noclvag_context_addr_sort(noclvag_context_t* vcp, void* buf);
extern void noclvag_context_thread_exit(noclvag_context_t* vcp);

/* Internal Init/cleanup for common execution context */
extern int noclvag_exec_context_init(noclvag_context_t* vcp,
                                     noclvag_exec_context_t* vxcp);
extern void noclvag_exec_context_del(noclvag_exec_context_t* vxcp);
extern void noclvag_exec_context_consolidate_key(noclvag_exec_context_t* vxcp);
extern void noclvag_exec_context_calc_pubkey(noclvag_exec_context_t* vxcp);
extern EC_KEY* noclvag_exec_context_new_key(void);

/* Internal execution context lock handling functions */
extern void noclvag_exec_context_downgrade_lock(noclvag_exec_context_t* vxcp);
extern int noclvag_exec_context_upgrade_lock(noclvag_exec_context_t* vxcp);
extern void noclvag_exec_context_yield(noclvag_exec_context_t* vxcp);

#endif /* !defined (__NOCLVAG_PATTERN_H__) */
