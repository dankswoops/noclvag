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

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "util-openssl.h"

void fprintbn(FILE* fp, const BIGNUM* bn) {
  char* buf;
  buf = BN_bn2hex(bn);
  fprintf(fp, "%s", buf ? buf : "0");
  if (buf) {
    OPENSSL_free(buf);
  }
}

void printbn(const BIGNUM* bn) { fprintbn(stdout, bn); }

int noclvag_set_privkey(const BIGNUM* bnpriv, EC_KEY* pkey) {
  const EC_GROUP* pgroup;
  EC_POINT* ppnt;
  int res;

  pgroup = EC_KEY_get0_group(pkey);
  ppnt = EC_POINT_new(pgroup);

  res = (ppnt && EC_KEY_set_private_key(pkey, bnpriv) &&
         EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
         EC_KEY_set_public_key(pkey, ppnt));

  if (ppnt) {
    EC_POINT_free(ppnt);
  }

  if (!res) {
    return 0;
  }

  assert(EC_KEY_check_key(pkey));
  return 1;
}
