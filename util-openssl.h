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

#if !defined(__NOCLVAG_UTIL_OPENSSL_H__)
#define __NOCLVAG_UTIL_OPENSSL_H__ 1

#include "globals.h"

#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

extern void fprintbn(FILE* fp, const BIGNUM* bn);
extern void printbn(const BIGNUM* bn);

extern int noclvag_set_privkey(const BIGNUM* bnpriv, EC_KEY* pkey);

#endif /* !defined (__NOCLVAG_UTIL_OPENSSL_H__) */
