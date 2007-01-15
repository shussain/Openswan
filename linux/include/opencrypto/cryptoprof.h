/*
 * This file is the kernel internal pieces of the Open Cryptographic Framework
 * This file is strictly used inside the kernel to track how much time is
 * spent on various bits.
 */

/*-
 * Copyright (c) 2006 Bart Trojanowski <bart@jukie.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Effort sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F30602-01-2-0537.
 *
 */
#ifndef _CRYPTO_CRYPTOPROF_H_
#define _CRYPTO_CRYPTOPROF_H_

#if defined(CONFIG_OCF_PROFILE)

#include <asm/msr.h>

/* these are the timestamps we keep track of for each cryptop */
typedef enum {
        // generic
        OCF_TS_RESET,

        // for crypto ops
        OCF_TS_CRP_DISPATCH,
        OCF_TS_CRP_PROCESS,
        OCF_TS_CRP_DONE,
        OCF_TS_CRP_DESTROY,

        // for the processing thread
        OCF_TS_PTH_WAKE,
        OCF_TS_PTH_RUN,
        OCF_TS_PTH_INVOKE,
        OCF_TS_PTH_SLEEP,

        // for the return thread
        OCF_TS_RTH_WAKE,
        OCF_TS_RTH_RUN,
        OCF_TS_RTH_CALLBACK,
        OCF_TS_RTH_SLEEP,

        // end
        OCF_TS_MAX
} cryptop_ts_type_t;
// make sure to update cryptop_ts_conf[] when updating the above

/* keep timestamps of state transitions the cryptop makes */
typedef struct cryptop_ts_s {

        u64 timestamp[OCF_TS_MAX];
        u64 mask;

} cryptop_ts_t;

extern int __init cryptop_ts_init (void);
extern void __exit cryptop_ts_exit (void);
extern void cryptop_ts_process (cryptop_ts_t *cts);

static inline void
cryptop_ts_record (cryptop_ts_t *cts, cryptop_ts_type_t type)
{
        if (((unsigned)type < OCF_TS_MAX) && !(cts->mask & (1 << type))) {
                rdtscll (cts->timestamp[type]);
                cts->mask |= 1 << type;
        }
}

static inline void
cryptop_ts_reset (cryptop_ts_t *cts)
{
        // OCF profilign cannot handle more then 64 timestamp
        BUG_ON (OCF_TS_MAX > 64);

        memset (&cts->mask, 0, sizeof (cts->mask));

        cryptop_ts_record (cts, OCF_TS_RESET);
}

static inline int
cryptop_ts_get (const cryptop_ts_t *cts, cryptop_ts_type_t type, u64 *val)
{
        if (cts->mask & (1 << type) && (unsigned)type < OCF_TS_MAX) {
                *val = cts->timestamp[type];
                return 0;
        }

        return -ENOENT;
}

#else

#define cryptop_ts_init()                ( 0 )
#define cryptop_ts_exit()                do { /* nothing */ } while (0)
#define cryptop_ts_reset(cts)            do { /* nothing */ } while (0)
#define cryptop_ts_record(cts, type)     do { /* nothing */ } while (0)
#define cryptop_ts_get(cts, type, val)   ( -EINVAL )
#define cryptop_ts_process(cts)          do { /* nothing */ } while (0)

#endif // CONFIG_OCF_PROFILE

#endif // _CRYPTO_CRYPTOPROF_H_
