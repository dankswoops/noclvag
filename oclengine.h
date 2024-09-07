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

#if !defined(__NOCLVAG_OCLENGINE_H__)
#define __NOCLVAG_OCLENGINE_H__ 1

#include <stdbool.h>

#include "globals.h"
#include "pattern.h"

typedef struct _noclvag_ocl_context_s noclvag_ocl_context_t;

extern void* noclvag_opencl_loop(noclvag_exec_context_t* arg);
extern noclvag_ocl_context_t*
noclvag_ocl_context_new(noclvag_context_t* vcp, int8_t platformidx,
                        int8_t deviceidx, bool safe_mode, bool verify,
                        uint32_t worksize, uint32_t nthreads, uint32_t nrows,
                        uint32_t ncols, uint32_t invsize);
extern void noclvag_ocl_context_free(noclvag_ocl_context_t* vocp);

extern noclvag_ocl_context_t*
noclvag_ocl_context_new_from_devstr(noclvag_context_t* vcp, const char* devstr,
                                    bool safemode, bool verify);

extern void noclvag_ocl_enumerate_devices(void);

#endif /* !defined (__NOCLVAG_OCLENGINE_H__) */
