/*
 * values for bits of debug_xform
 *
 */

#ifndef _IPSEC_DEBUG_H_

#define IPSEC_DBG_XFORM_RCV_SA       0x40
#define IPSEC_DBG_XFORM_RCV_SABYID  0x440
#define IPSEC_DBG_RATELIMITED       0x80000000
#define IPSEC_DBG_XFORM_XMIT_SA      0x80
#define IPSEC_DBG_XFORM_XMIT_SABYID 0x880

#define IPSEC_DBG_XFORM_SA_GENERIC  (1 << 0)
#define IPSEC_DBG_XFORM_SA_PROCEXTRA  (1 << 1)
#define IPSEC_DBG_XFORM_SA_TABLE    (1 << 2)
#define IPSEC_DBG_XFORM_SA_PUT      (1 << 27)
#define IPSEC_DBG_XFORM_SA_PUTFREE  (1 << 26)   /* 0x04000000 */
#define IPSEC_DBG_XFORM_SA_GET      (1 << 25)
#define IPSEC_DBG_SABYID_DETAIL     (1 << 12)   /* 0x00000400 */

#define IPSEC_DBG_XMIT_CROUT        (1 << 0)
#define IPSEC_DBG_XMIT_ERRORS       (1 << 1)
#define IPSEC_DBG_XMIT_NATT         (1 << 2)
#define IPSEC_DBG_XMIT_XSM          (1 << 3)
#define IPSEC_DBG_XMIT_SALOG        (1 << 4)
#define IPSEC_DBG_XMIT_LOGIPH       (1 << 5)

/* values for debug_tunnel --- old general purpose debug var */
#define DB_TN_INIT	0x0001
#define DB_TN_PROCFS	0x0002
#define DB_TN_XMIT	0x0010
#define DB_TN_OHDR	0x0020
#define DB_TN_CROUT	0x0040
#define DB_TN_OXFS	0x0080
#define DB_TN_REVEC	0x0100
#define DB_TN_ENCAP     0x0200

extern int debug_rcv;
extern int debug_ocf;
extern int debug_xform;
extern int debug_eroute;
extern int debug_spi;
extern int debug_netlink;
extern int debug_radij;
extern int debug_esp;
extern int debug_tunnel;
extern int debug_xmit;

/*
 * debugging routines.
 */
#define KLIPS_ERROR(flag, format, args...) if(printk_ratelimit() || (flag)) printk(KERN_ERR "KLIPS " format, ## args)
#ifdef CONFIG_KLIPS_DEBUG
	#define KLIPS_PRINT(flag, format, args...) \
                (((flag)&(~IPSEC_DBG_RATELIMITED)) ? printk(KERN_INFO format , ## args) : 0)
	#define KLIPS_PRINTMORE(flag, format, args...) \
                (((flag)&(~IPSEC_DBG_RATELIMITED)) ? printk(format , ## args) : 0)
	#define KLIPS_IP_PRINT(flag, ip) \
                (((flag)&(~IPSEC_DBG_RATELIMITED)) ? ipsec_print_ip(ip) : 0)
	#define KLIPS_SATOT(flag, sa, format, dst, dstlen) \
                (((flag)&(~IPSEC_DBG_RATELIMITED)) ? satot(sa, format, dst, dstlen) : 0)
        #define KLIPS_RATEDEBUG(flag, format, args...) if(unlikely((flag)&IPSEC_DBG_RATELIMITED) && printk_ratelimit()) printk(KERN_ERR "KLIPS " format, ## args)
#else /* CONFIG_KLIPS_DEBUG */
	#define KLIPS_PRINT(flag, format, args...) do ; while(0)
	#define KLIPS_PRINTMORE(flag, format, args...) do ; while(0)
	#define KLIPS_IP_PRINT(flag, ip) do ; while(0)
	#define KLIPS_SATOT(flag, sa, format, dst, dstlen) (0)
        #define KLIPS_RATEDEBUG(flag, format, args...) do ; while(0)
#endif /* CONFIG_KLIPS_DEBUG */

#ifdef CONFIG_KLIPS_SA_NEVERFREE
extern void ipsec_spi_verify_info(void);
#else
#define ipsec_spi_verify_info() do {} while(0)
#endif

#define _IPSEC_DEBUG_H_
#endif /* _IPSEC_DEBUG_H_ */
