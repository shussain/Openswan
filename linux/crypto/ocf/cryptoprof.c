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

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/compiler.h>
#include <opencrypto/crypto.h>
#include <opencrypto/cryptodev.h>
#include <opencrypto/cryptoprof.h>

#include <asm/div64.h>

/* 
 * table to configure periods to be displayed
 *
 * IDs are defined in the cryptop_ts_type_t enum, see cryptoprof.h
 *
 * A period has a start id, end id and name.  The end id of the period 
 * is also the index in the table.  The start id is stored in the table, 
 * as is the name given to the period.
 *
 * Any period that has a period_start of -1 is not displayed.  This is useful 
 * for having an arbitrary start of a profile period, that is not alos an end.
 */
static const struct {
        const char *name;
        cryptop_ts_type_t period_start;
} ocf_ts_conf[OCF_TS_MAX] = {
        /* limit strings to           "+------+" this much text */
        [OCF_TS_RESET]            = { "create",   -1,                  },
        // for crypto ops
        [OCF_TS_CRP_DISPATCH]     = { "dispatch", OCF_TS_RESET,        },
        [OCF_TS_CRP_PROCESS]      = { "process",  OCF_TS_CRP_DISPATCH, },
        [OCF_TS_CRP_DONE]         = { "done",     OCF_TS_CRP_PROCESS,  },
        [OCF_TS_CRP_DESTROY]      = { "destroy",  OCF_TS_CRP_DONE,     },
        // for the processing thread
        [OCF_TS_PTH_WAKE]         = { "pt.wake",  -1                   },
        [OCF_TS_PTH_RUN]          = { "pt.run",   OCF_TS_PTH_WAKE      },
        [OCF_TS_PTH_INVOKE]       = { "pt.invk",  OCF_TS_PTH_RUN       },
        [OCF_TS_PTH_SLEEP]        = { "pt.slp",   OCF_TS_PTH_RUN       },
        // for the processing thread
        [OCF_TS_RTH_WAKE]         = { "rt.wake",  -1                   },
        [OCF_TS_RTH_RUN]          = { "rt.run",   OCF_TS_RTH_WAKE      },
        [OCF_TS_RTH_CALLBACK]     = { "rt.clbk",  OCF_TS_RTH_RUN       },
        [OCF_TS_RTH_SLEEP]        = { "rt.slp",   OCF_TS_RTH_RUN       },
        /* limit strings to           "+------+" this much text */
};

static struct {

        u64             min_delta;
        u64             max_delta;
        u64             total_deltas;
        u32             count;
        unsigned long   reset_jiffies;  // last reset time

#define OCF_TS_DIST_MAX 12              // keep 12 buckets (keep even)
        /* distribution[x] counts the number of times an event took between
         * 10^(x-1) and 10^x nanoseconds (10^9) */
        u32             distribution[OCF_TS_DIST_MAX];  // [8^i,8^(i+1)]

} ocf_prof[OCF_TS_MAX];
static rwlock_t ocf_prof_lock;

/* this structure holds the maximum number of ticks that qualify an event to
 * fit in ocf_prof[].distribution[index] bucket. */
static uint64_t ocf_prof_dist_tick_max[OCF_TS_DIST_MAX] = {0,};
static uint64_t ocf_prof_dist_ns_max[OCF_TS_DIST_MAX] = {0,};

static __init int  cryptop_ts_init_proc (void);
static __exit void cryptop_ts_exit_proc (void);
static inline void __cryptop_ts_reset_all (void);
static inline void __cryptop_ts_reset_type (cryptop_ts_type_t type);

int __init 
cryptop_ts_init (void)
{
        int di;
        uint64_t ns, max_pre_overflow;
        uint32_t ticks_per_second;

        __cryptop_ts_reset_all ();

        rwlock_init (&ocf_prof_lock);

        cryptop_ts_init_proc ();

        // fill in the distribution conversion table so that...
        //   ocf_prof_dist_tick_max[di] = 10^di ns 
        // but converted to ticks
        ticks_per_second = loops_per_jiffy * HZ;
        max_pre_overflow = 1LL<<63;
        do_div (max_pre_overflow, ticks_per_second);
        for (di=0, ns=1; di<OCF_TS_DIST_MAX; di++, ns*=10) {

                uint64_t ticks;

                ocf_prof_dist_ns_max[di] = ns;

                // ticks = (ns / 1000_000_000) * (loops_per_jiffy * HZ)

                if ( ns < max_pre_overflow ) {
                        ticks = ns * ticks_per_second;
                        do_div (ticks, 1000*1000*1000);
                } else {
                        ticks = ns;
                        do_div (ticks, 1000*1000*1000);
                        ticks *= ticks_per_second;
                }

                ocf_prof_dist_tick_max[di] = ticks;
                //printk ("[%2d] % 17lld ns - %016llx clk\n", di, ns, ticks);
        }

        return 0;
}

void __exit 
cryptop_ts_exit (void)
{
        cryptop_ts_exit_proc ();
}

// ------------------------------------------------------------------------
// gathering and processing

/*
 * process timestamps after the cryptop finishes being processed
 */
void
cryptop_ts_process (cryptop_ts_t *cts)
{
        int di;
        cryptop_ts_type_t type;

        for (type=0; type<OCF_TS_MAX; type++) {

                int err;
                cryptop_ts_type_t start;
                u64 bgn, end, delta, new_total;
                u32 new_count;
                long lflags;

                start = ocf_ts_conf[type].period_start;
                if ((unsigned)start >= OCF_TS_MAX)
                        continue;

                err = cryptop_ts_get (cts, start, &bgn);
                if (err) continue;

                err = cryptop_ts_get (cts, type, &end);
                if (err) continue;

                if (bgn > end) continue;

                // now we have a valid begin and end timestamps
                delta = end - bgn;

                write_lock_irqsave (&ocf_prof_lock, lflags);

                new_total = ocf_prof[type].total_deltas + delta;
                new_count = ocf_prof[type].count + 1;

                if (ocf_prof[type].count 
                                && new_total > ocf_prof[type].total_deltas
                                && new_count > ocf_prof[type].count) {
                        // we don't wrap the total counter
                        ocf_prof[type].count = new_count;
                        ocf_prof[type].total_deltas = new_total;
                        if (ocf_prof[type].min_delta > delta)
                                ocf_prof[type].min_delta = delta;
                        if (ocf_prof[type].max_delta < delta)
                                ocf_prof[type].max_delta = delta;
                } else {
                        // reset due to overflow, or first entry
                        ocf_prof[type].count = 1;
                        ocf_prof[type].min_delta = delta;
                        ocf_prof[type].max_delta = delta;
                        ocf_prof[type].total_deltas = delta;
                        ocf_prof[type].reset_jiffies = jiffies;
                        memset (ocf_prof[type].distribution, 0, 
                                        sizeof (ocf_prof[type].distribution));
                }

                // decide which bucket we lie
                for (di=0; di<OCF_TS_DIST_MAX; di++) 
                        if (delta < ocf_prof_dist_tick_max[di])
                                break;
                ocf_prof[type].distribution[di] ++;

                write_unlock_irqrestore (&ocf_prof_lock, lflags);
        }
}

static inline void 
__cryptop_ts_reset_all (void)
{
        cryptop_ts_type_t type;

        for (type=0; type<OCF_TS_MAX; type++) {

                memset (&ocf_prof[type], 0, sizeof (ocf_prof[type]));
                ocf_prof[type].reset_jiffies = jiffies;

        }
}

static inline void 
__cryptop_ts_reset_type (cryptop_ts_type_t type)
{
        if ((unsigned)type < OCF_TS_MAX) {
                memset (&ocf_prof[type], 0, sizeof (ocf_prof[type]));
                ocf_prof[type].reset_jiffies = jiffies;
        }
}

// ------------------------------------------------------------------------
// /proc interface

static struct proc_dir_entry *ocf_proc = NULL;
static struct proc_dir_entry *ocf_proc_prof_times = NULL;
static struct proc_dir_entry *ocf_proc_prof_dists = NULL;

static int cryptop_ts_proc_times_read(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
static int cryptop_ts_proc_dists_read(char *page, char **start, off_t off,
			  int count, int *eof, void *data);
static int cryptop_ts_proc_write_to_clear(struct file *file, 
                const char __user *buffer, unsigned long count, void *data);

static char* cryptop_ts_conv (u64 val, char buf[32], int units_are_nanoseconds);

static __init int
cryptop_ts_init_proc (void)
{
        int rc;

        rc = -EACCES;
        ocf_proc = proc_mkdir ("ocf", proc_root_driver);
        if (!ocf_proc) {
                printk ("ocf: could not create /proc/driver/ocf/\n");
                goto error_mkdir_ocf;
        }

        ocf_proc_prof_times = create_proc_read_entry ("prof_times",
                        0444, ocf_proc, cryptop_ts_proc_times_read, NULL);
        if (!ocf_proc) {
                printk ("ocf: could not create /proc/driver/ocf/prof_times\n");
                goto error_times_entry;
        }
        ocf_proc_prof_times->write_proc = cryptop_ts_proc_write_to_clear;

        ocf_proc_prof_dists = create_proc_read_entry ("prof_dists",
                        0444, ocf_proc, cryptop_ts_proc_dists_read, NULL);
        if (!ocf_proc) {
                printk ("ocf: could not create /proc/driver/ocf/prof_dists\n");
                goto error_dists_entry;
        }
        ocf_proc_prof_dists->write_proc = cryptop_ts_proc_write_to_clear;

        return 0;

error_dists_entry:
        remove_proc_entry ("prof_times", ocf_proc);
error_times_entry:
        remove_proc_entry ("ocf", proc_root_driver);
error_mkdir_ocf:
        return rc;
}

static __exit void
cryptop_ts_exit_proc (void)
{
        remove_proc_entry ("prof_times", ocf_proc);
        remove_proc_entry ("prof_dists", ocf_proc);
        remove_proc_entry ("ocf", proc_root_driver);
}

static int 
cryptop_ts_proc_times_read(char *page, char **start, off_t off,
			  int len, int *eof, void *data)
{
        int rc;
        char *p, *e;
        char minbuf[16], avgbuf[16], maxbuf[16];
        cryptop_ts_type_t type;
        long lflags;

        p = page;
        e = p + len;
        *eof = 1;

        p += rc = snprintf (p, e-p, "profile min/avg/max times:\n");
        if (rc<0) goto error;

        for (type=OCF_TS_RESET; type<OCF_TS_MAX; type++) {

                cryptop_ts_type_t start;
                u32 count;
                u64 min = 0, avg = 0, max = 0;

                start = ocf_ts_conf[type].period_start;
                if ((unsigned)start >= OCF_TS_MAX)
                        continue;

                if (e-p < 80)
                        break;

                read_lock_irqsave (&ocf_prof_lock, lflags);

                count = ocf_prof[type].count;
                if (count) {
                        min = ocf_prof[type].min_delta;
                        max = ocf_prof[type].max_delta;
                        avg = ocf_prof[type].total_deltas;
                }

                read_unlock_irqrestore (&ocf_prof_lock, lflags);

                if (count)
                        do_div (avg, count);
                                        
                p += rc = snprintf (p, e-p, "%8s-%-8s : %9u : %9s / %9s / %9s\n",
                        ocf_ts_conf[start].name,
                        ocf_ts_conf[type].name,
                        count,
                        cryptop_ts_conv (min, minbuf, 0),
                        cryptop_ts_conv (avg, avgbuf, 0),
                        cryptop_ts_conv (max, maxbuf, 0));
                if (rc<0) goto error;

#if 0
                p += rc = snprintf (p, e-p, "                             - "
                                "%9lld / %9lld / %9lld\n", min, avg, max);
                if (rc<0) goto error;
#endif
        }

#if 0
        p += rc = snprintf (p, e-p, "loops_per_jiffy=%lu HZ=%u\n",
                        loops_per_jiffy, HZ);
        if (rc<0) goto error;
#endif

        rc = p-page;

error:
        return rc;
}

static int 
cryptop_ts_proc_dists_read(char *page, char **start, off_t off,
			  int len, int *eof, void *data)
{
        int rc, di;
        char *p, *e;
        char buf[16];
        cryptop_ts_type_t type;
        long lflags;

        p = page;
        e = p + len;
        *eof = 1;

        p += rc = snprintf (p, e-p, "statistical distribution:\n"
                        "                   ""  0ns       ");
        if (rc<0) goto error;

        for (di=1; di<OCF_TS_DIST_MAX-1; di+=2) {
                u64 val;

                val = ocf_prof_dist_ns_max[di];

                p += rc = snprintf (p, e-p, "%-11s ", 
                                cryptop_ts_conv (val, buf, 1));
                if (rc<0) goto error;
        }

        p += rc = snprintf (p, e-p, "inf\n"
                        "                   ""      ");
        if (rc<0) goto error;

        for (di=0; di<OCF_TS_DIST_MAX-1; di+=2) {
                u64 val;

                val = ocf_prof_dist_ns_max[di];

                p += rc = snprintf (p, e-p, "%-11s ", 
                                cryptop_ts_conv (val, buf, 1));
                if (rc<0) goto error;
        }

        if (rc) *(p-1) = '\n';
        *p = 0;

        for (type=OCF_TS_RESET; type<OCF_TS_MAX; type++) {

                cryptop_ts_type_t start;
                u32 dtmp[OCF_TS_DIST_MAX];

                start = ocf_ts_conf[type].period_start;
                if ((unsigned)start >= OCF_TS_MAX)
                        continue;

                if (e-p < 160)
                        break;

                p += rc = snprintf (p, e-p, "%8s-%-8s : ",
                        ocf_ts_conf[start].name,
                        ocf_ts_conf[type].name);
                if (rc<0) goto error;

                read_lock_irqsave (&ocf_prof_lock, lflags);

                memcpy (dtmp, ocf_prof[type].distribution, sizeof (dtmp));

                read_unlock_irqrestore (&ocf_prof_lock, lflags);

                for (di=0; di<OCF_TS_DIST_MAX; di++) {
                        p += rc = snprintf (p, e-p, "%5d ", dtmp[di]);
                        if (rc<0) goto error;
                }

                if (rc) *(p-1) = '\n';
                *p = 0;
        }

        rc = p-page;

error:
        return rc;
}

static int 
cryptop_ts_proc_write_to_clear(struct file *file, 
                const char __user *buffer, unsigned long count, void *data)
{
        unsigned long lflags;

        if (count>0) {
                write_lock_irqsave (&ocf_prof_lock, lflags);
                __cryptop_ts_reset_all ();
                write_unlock_irqrestore (&ocf_prof_lock, lflags);
        }

        return count;
}

static char* 
cryptop_ts_conv (u64 ticks, char buf[16], int units_are_nanoseconds)
{
        int rc;
        u64 val64;
        u32 whole, decimal;
        const char *unitchars[] = { "n", "u", "m", "", "k", "M", "G", "T", "Y", "Z", NULL };
        const char **unit = unitchars;

        if (units_are_nanoseconds) {

                // the value is already in nanoseconds
                val64 = ticks;
        
        } else if (ticks < (LLONG_MAX/1000000000LL)) {

                // convert val to nanoseconds
                // val = (ticks / loops_per_jiffy) in jiffies
                val64 = ticks * 1000000000LL;
                do_div (val64, loops_per_jiffy);
                do_div (val64, HZ);

        } else {
                // the number is large enough that we can do it in a less
                // precise way

                val64 = ticks;
                do_div (val64, loops_per_jiffy);
                val64 *= 1000000 /  HZ;
        }

        // scale down to 99,999 + unit
        while (val64 > 100000) {
                unit ++;
                do_div (val64, 1000);
                if(!*(unit+1)) return "(eunit)";
        }

        if (unlikely (val64 > UINT_MAX))
                return "(erange)";

        // generate a decimal component if it makes sense
        whole = val64;
        decimal = 0;
        if (whole >= 1000 && *(unit+1)) {
                decimal = whole % 1000;
                whole = whole / 1000;
                unit++;
        }

        // print the output
        if (decimal)
                rc = snprintf (buf, 16, "%u.%03u%ss", whole, decimal, *unit);
        else
                rc = snprintf (buf, 16, "%u%ss", whole, *unit);

        if (rc<0) 
                return "(efmt)";

        return buf;
}


