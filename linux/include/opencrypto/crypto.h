/*	$FreeBSD: src/sys/opencrypto/cryptodev.h,v 1.23 2006/06/04 22:15:13 pjd Exp $	*/
/*	$OpenBSD: cryptodev.h,v 1.31 2002/06/11 11:14:29 beck Exp $	*/

/*
 * This file is the kernel internal pieces of the Open Cryptographic Framework
 * These things have been moved from cryptodev.h, which is now strictly a
 * userspace interface file.  Only this file should contain *BSD/Linux
 * specific parts.
 *
 * The default assumption should be *BSD (FreeBSD), with linux being
 * the exception case. 
 *
 */

/*-
 * Many additions by Michael Richardson <mcr@xelerance.com> and
 *                   Bart Trojanowski <bart@jukie.net> in 2006 under
 *                   contract with Hifn inc.
 *
 * Linux port done by David McCullough <dmccullough@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  All Rights Reserved.
 * The license and original author are listed below.
 *
 * The author of this code is Angelos D. Keromytis (angelos@cis.upenn.edu)
 *
 * This code was written by Angelos D. Keromytis in Athens, Greece, in
 * February 2000. Network Security Technologies Inc. (NSTI) kindly
 * supported the development of this code.
 *
 * Copyright (c) 2000 Angelos D. Keromytis
 *
 * Permission to use, copy, and modify this software with or without fee
 * is hereby granted, provided that this entire notice is included in
 * all source code copies of any software which is or includes a copy or
 * modification of this software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTY. IN PARTICULAR, NONE OF THE AUTHORS MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE
 * MERCHANTABILITY OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR
 * PURPOSE.
 *
 * Copyright (c) 2001 Theo de Raadt
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

#ifndef _CRYPTO_CRYPTO_H_
#define _CRYPTO_CRYPTO_H_

#if !defined(__KERNEL__) && !defined(_KERNEL)
#warning do not include this from userspace
#endif

#include <opencrypto/cryptodev.h>
#include <opencrypto/cryptoprof.h>

/* Some initial values */
#define CRYPTO_DRIVERS_INITIAL	4
#define CRYPTO_SW_SESSIONS	32

/* Standard initialization structure beginning */
struct cryptoini {
	int		cri_alg;	/* Algorithm to use */
	int		cri_klen;	/* Key length, in bits */
	int		cri_mlen;	/* Number of bytes we want from the
					   entire hash. 0 means all. */
	int		cri_rnd;	/* Algorithm rounds, where relevant */
	caddr_t		cri_key;	/* key to use */
	u_int8_t	cri_iv[EALG_MAX_BLOCK_LEN];	/* IV to use */
	struct cryptoini *cri_next;
};

/* Describe boundaries of a single crypto operation */
struct cryptodesc {
	int		crd_skip;	/* How many bytes to ignore from start */
	int		crd_len;	/* How many bytes to process */
	int		crd_inject;	/* Where to inject results, if applicable */
	int		crd_flags;

#define	CRD_F_ENCRYPT		0x01	/* Set when doing encryption */
#define	CRD_F_IV_PRESENT	0x02	/* When encrypting, IV is already in
					   place, so don't copy. */
#define	CRD_F_IV_EXPLICIT	0x04	/* IV explicitly provided */
#define	CRD_F_DSA_SHA_NEEDED	0x08	/* Compute SHA-1 of buffer for DSA */
#define	CRD_F_KEY_EXPLICIT	0x10	/* Key explicitly provided */
#define CRD_F_COMP		0x0f    /* Set when doing compression */

	struct cryptoini	CRD_INI; /* Initialization/context data */
#define crd_iv		CRD_INI.cri_iv
#define crd_key		CRD_INI.cri_key
#define crd_rnd		CRD_INI.cri_rnd
#define crd_alg		CRD_INI.cri_alg
#define crd_klen	CRD_INI.cri_klen

	struct cryptodesc *crd_next;
};

/* Structure describing complete operation */
struct cryptop {
#if defined(linux)
	struct list_head crp_list;
	wait_queue_head_t crp_waitq;
#else
	TAILQ_ENTRY(cryptop) crp_next;
#endif

	u_int64_t	crp_sid;	/* Session ID */
	int		crp_ilen;	/* Input data total length */
	int		crp_olen;	/* Result total length 
                                         * Only modified after (de)compression.
					 * Note: crp_olen is updated to the sum
					 * of the result data + crd_inject.
					 */

	int		crp_etype;	/*
					 * Error type (zero means no error).
					 * All error codes except EAGAIN
					 * indicate possible data corruption (as in,
					 * the data have been touched). On all
					 * errors, the crp_sid may have changed
					 * (reset to a new one), so the caller
					 * should always check and use the new
					 * value on future requests.
					 * ERANGE -- is compression fails.
					 */
	int		crp_flags;

#if defined(linux)
#define CRYPTO_F_SKBUF		0x0001	/* Input/output are skbuf chains */
#else
#define CRYPTO_F_IMBUF		0x0001	/* Input/output are mbuf chains */
#endif

#define CRYPTO_F_IOV		0x0002	/* Input/output are uio */
#define CRYPTO_F_REL		0x0004	/* Must return data in same place */
#define	CRYPTO_F_BATCH		0x0008	/* Batch op if possible */
#define	CRYPTO_F_CBIMM		0x0010	/* Do callback immediately */
#define	CRYPTO_F_DONE		0x0020	/* Operation completed */
#define	CRYPTO_F_CBIFSYNC	0x0040	/* Do CBIMM if op is synchronous */

	caddr_t		crp_buf;	/* Data to be processed */
	caddr_t		crp_opaque;	/* Opaque pointer, passed along */
	struct cryptodesc *crp_desc;	/* Linked list of processing descriptors */

	int (*crp_callback)(struct cryptop *); /* Callback function */

#if !defined(linux)
	struct bintime	crp_tstamp;	/* performance time stamp */
#endif
	caddr_t		crp_mac;
	int             crp_maclen;     /* size of buffer above */

#if defined(CONFIG_OCF_PROFILE)
        cryptop_ts_t    crp_times;
#endif
};

#define CRYPTO_BUF_CONTIG	0x0
#define CRYPTO_BUF_IOV		0x1

#if defined(linux)
#define CRYPTO_BUF_SKBUF	0x2
#else
#define CRYPTO_BUF_MBUF		0x2
#endif

#define CRYPTO_OP_DECRYPT	0x0
#define CRYPTO_OP_ENCRYPT	0x1

/*
 * Hints passed to process methods.
 */
#define	CRYPTO_HINT_MORE	0x1	/* more ops coming shortly */

/* 
 * Selecting a devicy by wildcard
 */
enum cryptodev_selection {
	CRYPTO_ANYDEVICE=-1,
	CRYPTO_ANYHARDWARE=-2,
	CRYPTO_ANYSOFTWARE=-3,
	CRYPTO_SOFTWARE=0,
	/* otherwise, specific driver */
};
#define CRYPTODEV_SELECTION_MIN CRYPTO_ANYSOFTWARE

struct cryptkop {
#if defined(linux)
	struct list_head krp_list;
	wait_queue_head_t krp_waitq;
#else
	TAILQ_ENTRY(cryptkop) krp_next;
#endif

	int		krp_flags;
#define	CRYPTO_KF_DONE		0x0001	/* Operation completed */
#define	CRYPTO_KF_CBIMM		0x0002	/* Do callback immediately */

	u_int		krp_op;		/* ie. CRK_MOD_EXP or other */
	u_int		krp_status;	/* return status */
	u_short		krp_iparams;	/* # of input parameters */
	u_short		krp_oparams;	/* # of output parameters */
	enum cryptodev_selection krp_desired_device; /* desired device */
	u_int32_t	krp_hid;	/* selected device */
	struct crparam	krp_param[CRK_MAXPARAM];	/* kvm */
	int		(*krp_callback)(struct cryptkop *);
};

/*
 * Crypto capabilities structure.
 *
 * Synchronization:
 * (d) - protected by CRYPTO_DRIVER_LOCK()
 * (q) - protected by CRYPTO_Q_LOCK()
 * Not tagged fields are read-only.
 */
struct cryptocap {
	u_int32_t	cc_sessions;		/* (d) number of sessions */
	u_int32_t	cc_koperations;		/* (d) number os asym operations */
	u_int32_t       cc_hid;
	char            cc_name[CRYPTO_NAME_LEN];

	/*
	 * Largest possible operator length (in bits) for each type of
	 * encryption algorithm.
	 */
	u_int16_t	cc_max_op_len[CRYPTO_ALGORITHM_MAX + 1];

	u_int8_t	cc_alg[CRYPTO_ALGORITHM_MAX + 1];

	u_int8_t	cc_kalg[CRK_ALGORITHM_MAX + 1];

	u_int8_t	cc_flags;		/* (d) flags */
#define CRYPTOCAP_F_CLEANUP	0x01		/* needs resource cleanup */
#define CRYPTOCAP_F_SOFTWARE	0x02		/* software implementation */
#define CRYPTOCAP_F_SYNC	0x04		/* operates synchronously */
	u_int8_t	cc_qblocked;		/* (q) symmetric q blocked */
	u_int8_t	cc_kqblocked;		/* (q) asymmetric q blocked */

	void		*cc_arg;		/* callback argument */
	int		(*cc_newsession)(void*, u_int32_t*, struct cryptoini*);
	int		(*cc_process)(void*, struct cryptop *, int);
	int		(*cc_freesession)(void*, u_int64_t);
	void		*cc_karg;		/* callback argument */
	int		(*cc_kprocess) (void*, struct cryptkop *, int);
};

/*
 * Session ids are 64 bits.  The lower 32 bits contain a "local id" which
 * is a driver-private session identifier.  The upper 32 bits contain a
 * "hardware id" used by the core crypto code to identify the driver and
 * a copy of the driver's capabilities that can be used by client code to
 * optimize operation.
 */
#define	CRYPTO_SESID2HID(_sid)	(((_sid) >> 32) & 0xffffff)
#define	CRYPTO_SESID2CAPS(_sid)	(((_sid) >> 56) & 0xff)
#define	CRYPTO_SESID2LID(_sid)	(((u_int32_t) (_sid)) & 0xffffffff)

#if !defined(linux)
MALLOC_DECLARE(M_CRYPTO_DATA);
#endif

extern	int crypto_newsession(u_int64_t *sid, struct cryptoini *cri, enum cryptodev_selection desired_device);
extern	int crypto_freesession(u_int64_t sid);
extern	int32_t crypto_get_driverid(u_int32_t flags, const char *drivername);
extern  int crypto_find_driverid (const char *drivername, int32_t *found_id);
extern  void crypto_devicename(u_int64_t sid, char devicename[16]);
extern  void crypto_get_devicename(u_int32_t device_id, char devicename[CRYPTO_NAME_LEN]);
extern  void crypto_get_sess_devicename (u_int64_t sid, char devicename[CRYPTO_NAME_LEN]);
extern	int crypto_register(u_int32_t driverid, int alg, u_int16_t maxoplen,
	    u_int32_t flags,
	    int (*newses)(void*, u_int32_t*, struct cryptoini*),
	    int (*freeses)(void*, u_int64_t),
	    int (*process)(void*, struct cryptop *, int),
	    void *arg);
extern	int crypto_kregister(u_int32_t, int, u_int32_t,
	    int (*)(void*, struct cryptkop *, int),
	    void *arg);
extern	int crypto_unregister(u_int32_t driverid, int alg);
extern	int crypto_unregister_all(u_int32_t driverid);
extern	int crypto_dispatch(struct cryptop *crp);
extern	int crypto_kdispatch(struct cryptkop *);
#define	CRYPTO_SYMQ	0x1
#define	CRYPTO_ASYMQ	0x2
extern	int crypto_unblock(u_int32_t, int);
extern	void crypto_done(struct cryptop *crp);
extern	void crypto_kdone(struct cryptkop *);
extern	int crypto_getfeat(int *);

extern	void crypto_freereq(struct cryptop *crp);
extern	struct cryptop *crypto_getreq(int num);

#if 0
extern	int crypto_usercrypto;		/* userland may do crypto requests */
extern	int crypto_userasymcrypto;	/* userland may do asym crypto reqs */
extern	int crypto_devallowsoft;	/* only use hardware crypto */
#endif

/*
 * random number support,  crypto_unregister_all will unregister
 */
extern int crypto_rregister(u_int32_t driverid,
		int (*read_random)(void *arg, u_int32_t *buf, int len), void *arg);
extern int crypto_runregister_all(u_int32_t driverid);

/*
 * Crypto-related utility routines used mainly by drivers.
 *
 * XXX these don't really belong here; but for now they're
 *     kept apart from the rest of the system.
 */
struct uio;
extern	void cuio_copydata(struct uio* uio, int off, int len, caddr_t cp);
extern	void cuio_copyback(struct uio* uio, int off, int len, caddr_t cp);
extern	struct iovec *cuio_getptr(struct uio *uio, int loc, int *off);
#if !defined(linux)
extern	int cuio_apply(struct uio *uio, int off, int len,
	    int (*f)(void *, void *, u_int), void *arg);
#endif

extern	void crypto_copyback(int flags, caddr_t buf, int off, int size,
	    caddr_t in);
extern	void crypto_copydata(int flags, caddr_t buf, int off, int size,
	    caddr_t out);
extern	int crypto_apply(int flags, caddr_t buf, int off, int len,
	    int (*f)(void *, void *, u_int), void *arg);

/*
 * common debug for all
 */
#if 1
#define dprintk(a...)	if (debug) { printk(a); } else
#else
#define dprintk(a...)
#endif

/*
 * iomem support for 2.4 qand 2.6 kernels
 */
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define ocf_iomem_t	unsigned long

/*
 * implement simple workqueue like support for older kernels
 */

#include <linux/tqueue.h>

#define work_struct tq_struct

#define INIT_WORK(wp, fp, ap) \
	do { \
		(wp)->sync = 0; \
		(wp)->routine = (fp); \
		(wp)->data = (ap); \
	} while (0)

#define schedule_work(wp) \
	do { \
		queue_task((wp), &tq_immediate); \
		mark_bh(IMMEDIATE_BH); \
	} while (0)

#define flush_scheduled_work()	run_task_queue(&tq_immediate)


#else
#define ocf_iomem_t	void __iomem *

#include <linux/workqueue.h>

#endif

#endif /* _CRYPTO_CRYPTO_H_ */
