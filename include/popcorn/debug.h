#ifndef __INCLUDE_POPCORN_DEBUG_H__
#define __INCLUDE_POPCORN_DEBUG_H__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>

#define MICROSECOND 1000000
#define KVMCLOCKPK(...)

#define POPCORN_MQ_VIRTIO_BLK
#define CONFIG_POPCORN_ORIGIN_NODE
#define POPCORN_TUN_PORTHASH

/*
* Host debug macros
*/
//#define VIRTIOBLKPK(...) 	printk("virtio-blk: " __VA_ARGS__)
#define VIRTIOBLKPK(...)

//#define VHOSTPK(...) printk(KERN_INFO "vhost_pk: " __VA_ARGS__)
#define VHOSTPK(...)
//#define VHOSTPKRX(...) printk(KERN_INFO "vhost_pk_rx: " __VA_ARGS__)
#define VHOSTPKRX(...)
//#define VHOSTPKTX(...) printk(KERN_INFO "vhost_pk_tx: " __VA_ARGS__)
#define VHOSTPKTX(...)
//#define VHOSTPKIRQ(...) printk(KERN_INFO "vhost_pk_irq: " __VA_ARGS__)
#define VHOSTPKIRQ(...)
#define VHOSTPKTUN(...) trace_printk("vhost_pk_tun: " __VA_ARGS__)
//#define VHOSTPKTUN(...)

/*
* Guest virtio debug macros
*/
//#define VIRTIOPK(...) printk(KERN_INFO "vhost_pk: " __VA_ARGS__)
#define VIRTIOPK(...)
//#define VIRTIOPKRX(...) printk(KERN_INFO "vhost_pk_rx: " __VA_ARGS__)
#define VIRTIOPKRX(...)
//#define VIRTIOPKTX(...) printk(KERN_INFO "vhost_pk_tx: " __VA_ARGS__)
#define VIRTIOPKTX(...)
//#define VIRTIOPKIRQ(...) printk(KERN_INFO "vhost_pk_irq: " __VA_ARGS__)
#define VIRTIOPKIRQ(...)

#define PCNPRINTK(...) printk(KERN_INFO "popcorn: " __VA_ARGS__)
#define PCNPRINTK_ERR(...) printk(KERN_ERR "popcorn: " __VA_ARGS__)

/*
 * Function macros
 */
#ifdef CONFIG_POPCORN_DEBUG
#define PRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define PRINTK(...)
#endif


#ifdef CONFIG_POPCORN_DEBUG_PROCESS_SERVER
#define PSPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define PSPRINTK(...)
#endif


#ifdef CONFIG_POPCORN_DEBUG_VMA_SERVER
#define VSPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define VSPRINTK(...)
#endif


#ifdef CONFIG_POPCORN_DEBUG_PAGE_SERVER
#define PGPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define PGPRINTK(...)
#endif


#ifdef CONFIG_POPCORN_DEBUG_MSG_LAYER
#define MSGPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define MSGPRINTK(...)
#endif


#ifdef CONFIG_POPCORN_DEBUG_HYPE
#define HPPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define HPPRINTK(...) ;
#endif


#ifdef CONFIG_POPCORN_DEBUG_HYPE_EPT
#define EPTPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define EPTPRINTK(...) ;
#endif

#ifdef CONFIG_POPCORN_DEBUG_HYPE_EPT_MORE
#define EPTMPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define EPTMPRINTK(...) ;
#endif

/* usable */
#ifdef CONFIG_POPCORN_DEBUG_HYPE_EPT_VERBOSE
#define EPTVPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define EPTVPRINTK(...) ;
#endif

#define EPTVVPRINTK(...) ;

#ifdef CONFIG_POPCORN_DEBUG_DEBUG
#define DDPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#else
#define DDPRINTK(...) ;
#endif

/*************** THE ONLY IMPORTANT TUNNING KNOBS IN THIS FILE **************/
/* CHECK make menuconfig for other printks */
#define PERF_EXP 1 /* 0: development 1: get # */
/* pophype DSM debug - check bool pophype_debug in page_server.c */

/* Give me a clean pophype (0 printk) -
 *		used only when getting init time
 */
#define POP_CLEAN 1 /* Make sure CONFIG_POPCORN_STAT off */
#if POP_CLEAN
/* essential debug messages -
 *		turn off only if measuring init time
 */
#define POP_PK(...) ;
#else
#define POP_PK(...) printk(KERN_INFO __VA_ARGS__);
#endif

/* init time - always on */
#define POP_INIT_TIME 1
#define POP_INIT_TIME_PK(...) ; //printk(KERN_INFO __VA_ARGS__);

/* 1st version network optimization (not working) */
#define POPHYPE_NET_OPTIMIZE 0 /* rely on POPHYPE_HOST_KERNEL */
#define POPHYPE_NET_OPTIMIZE_TMP_DEBUG 0 // temporary debugging info for optimizing network
#define POP_NET_PK_TMP(...) ; // printk(KERN_INFO __VA_ARGS__)

/* mq debug */
#define POPCORN_STAT_MQ_INFO 0

/* ft debug */
#define POPCORN_DEBUG_FT 0

#define GUEST_KERNEL_OPTIMIZE 1 /* search "pophype - dsm traffic" to find them */
/* ATTENTION: manually check these files since it cannot include <popcorn/debug.h>
 * ./arch/x86/include/asm/pvclock-abi.h - sturct pvclock_vcpu_time_info {} // AB suggests to only change this
 * ./include/linux/hrtimer.h - struct hrtimer_cpu_base {}
 *
 * For our convinice to test them one by one
 * ./arch/x86/kvm/vmx.c - EPT_AD
 * ./arch/x86/kernel/pvclock.c - last_value alignment
 */

#define GUEST_KERNEL_OPTIMIZE_EPT_AD 1

#define EPT_RETRY_VM_OPTIMIZE 1 /* under developemnt - make sure this is 0 when collecting #s */

/* Workitem: remove msleep() in int __init shmem_init(void) and more...
 * 	_cpu_up();
 */

/****
 * Exceptions needing your attention
 */
/* Happens when ramdisk is to large and relocated to a new region -
 * this printk will print forever
 */
#define MMIOPK(...) ; //printk(KERN_INFO __VA_ARGS__);

/* Performace critial
 *	- DSMPATCHPK - compromise with dsm shortage (can only support 1 pg at a time)
 */
#if PERF_EXP
#define CRITICALNETPK(...) ;
#define CRITICALIOPK(...) ;
#define CRITICALALLPK(...) ;
#define DSMPATCHPK(...) ;
#else
#define CRITICALNETPK(...) printk(KERN_INFO __VA_ARGS__) /* guest has (not debugging now) */
//#define CRITICALNETPK(...) ;
#define CRITICALIOPK(...) printk(KERN_INFO __VA_ARGS__)
#define CRITICALALLPK(...) printk(KERN_INFO __VA_ARGS__)
//#define DSMPATCHPK(...) printk(KERN_INFO __VA_ARGS__) /* DSM NET PATCH (!handle < 1 pg) */
#define DSMPATCHPK(...) ;
#endif


#if PERF_EXP
#define HYPE_PERF_CRITICAL_DEBUG 0 /* This will turn on debug msg and harm the performance */
#define HYPE_PERF_CRITICAL_IPI_DEBUG 0
#define HYPE_PERF_CRITICAL_DSM_TRAFFIC_DEBUG 0
#define HYPE_PERF_CRITICAL_DSM_TRAFFIC_PRINTK 0
#define HYPE_PERF_DSM_TRAFFIC_PK 0
#define DSM_COLLECT_PK(...) ;
//#define VHOSTNET_OPTIMIZE_PK(...) printk(KERN_INFO __VA_ARGS__)
#define VHOSTNET_OPTIMIZE_PK(...) ;
#define HYPE_PERF_CRITICAL_MSG_DEBUG 0 /* msg rb util */
#define HYPE_PERF_CRITICAL_NET_DEBUG 0 /* net related not used */
#define HYPE_PERF_NET_DEBUG 0
#else
#define HYPE_PERF_CRITICAL_DEBUG 0 /* This will turn on debug msg and harm the performance */
#define HYPE_PERF_CRITICAL_IPI_DEBUG 0
#define HYPE_PERF_CRITICAL_DSM_TRAFFIC_DEBUG 1 /* use /proc/popcorn_debug */
#define HYPE_PERF_CRITICAL_DSM_TRAFFIC_PRINTK 0 /* traslation host addr to guest rip */
#define HYPE_PERF_DSM_TRAFFIC_PK 1
#define DSM_COLLECT_PK(...) printk(KERN_INFO __VA_ARGS__)
#define VHOSTNET_OPTIMIZE_PK(...) printk(KERN_INFO __VA_ARGS__)
//#define VHOSTNET_OPTIMIZE_PK(...) ;
#define HYPE_PERF_CRITICAL_MSG_DEBUG 0 /* msg rb util */
#define HYPE_PERF_CRITICAL_NET_DEBUG 0 /* net related not used */
#define HYPE_PERF_NET_DEBUG 1
#endif

#if PERF_EXP
#define VM_DSM_COLLECT_PK(...)
#else
#define VM_DSM_COLLECT_PK(...) printk(KERN_INFO __VA_ARGS__) /* vm dsm stack walk*/
#endif

#define OPENLAMBDA_EXP 1

/* Not perf critical but system-crash critical -
 *		turn off for long runtime init process e.g. openlambda's systemd.
 * If not openlambda/systemd, turn it on since it's not perf critical.
 */
#if OPENLAMBDA_EXP
#define IRQINITPK(...) ;
#else
#define IRQINITPK(...) printk(KERN_INFO __VA_ARGS__)
#endif


/* Popcorn-hype 1: host 0: guest */
#define POPHYPE_HOST_KERNEL 1
#define POPHYPE_GUEST_DEBUG_CPU 1
#define POPHYPE_GUEST_DEBUG_NODE 1

/* Pophype + guest + net optimize */
#if defined(CONFIG_POPCORN_HYPE) && !POPHYPE_HOST_KERNEL && POPHYPE_NET_OPTIMIZE
#define POPHYPE_GUEST_NET_OPTIMIZE 1
#else
#define POPHYPE_GUEST_NET_OPTIMIZE 0
#endif


/* 1: yes 0: not interested in any address */
#define INTERESTED_ADDRS 1

/* Pophype migration */
#if PERF_EXP
#define HPMIGRATION_DEBUG 0
//#define HPMIGRATION_DEBUG 1 /* debug: ft */
//#define POPHYPE_MIGRATE_DEBUG 1
#define POPHYPE_MIGRATE_DEBUG 0
//#define PHGMIGRATEPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* debug: ft */
#define PHGMIGRATEPRINTK(...)
//#define PHMIGRATEPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* debug: ft */
#define PHMIGRATEPRINTK(...)
#define FTPRINTK(...)
//#define POPHYPE_MIGRATE_VERBOSE_DEBUG 1 // debug: ft
#define POPHYPE_MIGRATE_VERBOSE_DEBUG 0
#define PHMIGRATEVPRINTK(...)

#define VPCINETPRINTK(...) ;
#define POPHYPE_APIC_DEBUG 0
#define PHAPICPRINTK(...)
#define VCPUPRINTK(...)
#define PHMSRPRINTK(...)
#else
//#define HPMIGRATION_DEBUG 0
#define POPHYPE_MIGRATE_DEBUG 1
#define PHMIGRATEPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define PHGMIGRATEPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define POPHYPE_MIGRATE_VERBOSE_DEBUG 0
#define PHMIGRATEVPRINTK(...) /* sub pophype migration */
#define FTPRINTK(...) printk(KERN_INFO __VA_ARGS__)

#define VPCINETPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define PHAPICPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define VCPUPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define POPHYPE_APIC_DEBUG 1
#define PHMSRPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#endif
/* PHMIGRATEPRINTK and POPHYPE_MIGRATE_DEBUG include lots vCPU related essential states */
/* Workitem: #if defined(CONFIG_POPCORN_HYPE) && defined(CONFIG_POPCORN_STAT)
 *				=> #if defined(CONFIG_POPCORN_HYPE) && POPHYPE_MIGRATE_DEBUG
 *			- move PHAPICPRINTK outside to here
 *			- MAKE SURE boot_cmd has no apic_debug
 */
/* Pophype migration end */


/* Hype-popcorn fine grained debug log (perf-related) too verbose */
#if PERF_EXP
#define IPIPRINTK(...) ; /* you usually want this on except doing exp */
#define IPIVPRINTK(...) ;
//#define SIGVPRINTK(...) ;
#define SIGVPRINTK(...) ; //printk(KERN_INFO __VA_ARGS__)  /* debug: ft */
#else
#define IPIPRINTK(...) ; /* periodically */
#define IPIVPRINTK(...) ;
//#define IPIPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* you usually want this on except doing exp */
//#define IPIVPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* cannot boot */
#define SIGVPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#endif


/* Boot time pophype debug msg */
#if PERF_EXP
#define HYPEBOOTDBGPRINTK(...) ;
#define HYPECKPTPRINTK(...) ;
//#define HYPEBOOTDEBUG 1
#define HYPEBOOTDEBUG 0 /* Speed up boot time */
#define WRMSRPRINTK(...)
#else
#define HYPEBOOTDBGPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define HYPECKPTPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define HYPEBOOTDEBUG 1 /* Speed up boot time */
#define WRMSRPRINTK(...)
#endif


#if POP_CLEAN
#define IPIINITPRINTK(...) ;
#define SIPIPRINTK(...) ;
#define SMPPRINTK(...) ;
#define SMPBSPPRINTK(...) ;
#define SMPAPPRINTK(...) ;
#define APICIRQPRINTK(...) ;
#define FUTEXPRINTK(...) ;
#define FDPRINTK(...) ;
#define VMPRINTK(...) ;
#define DBGPRINTK(...) ;
#define UARTPRINTK(...) ;
#define IRQCHIPPRINTK(...) ;
#define AFFPRINTK(...) ;
#define IRQPROCPRINTK(...) ;
#define LKPRINTK(...) ;
#define GUPFASTPRINTK(...) ;
#define DSMRETRYPRINTK(...) ;
#define NOTIFYCHAINPRINTK(...) ;
#define VCPUTONIDPRINTK(...) ;
#define KVMINITRINTK(...) ;
#define GSMPBSPPRINTK(...) ;
#define GSMPPRINTK(...) ;
#define GBSPIPIPRINTK(...) ;
#define GSMPIPIRESCHEDPRINTK(...) ;
#else /* else POP_CLEAN*/
#define IPIINITPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define SIPIPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define SMPPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define SMPBSPPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define SMPAPPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define APICIRQPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define FUTEXPRINTK(...) ;
#define FDPRINTK(...) ;
#define VMPRINTK(...) ;
#define DBGPRINTK(...) ;
#define UARTPRINTK(...) ;
#define IRQCHIPPRINTK(...) ;
#define AFFPRINTK(...) ; /* irq affinity for PCI-MSI //not verbose */
//#define AFFPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define IRQPROCPRINTK(...) ;
//#define IRQPROCPRINTK(...) printk(KERN_INFO __VA_ARGS__)

/* Lock */
//#define LKPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* up_read() debug */
#define LKPRINTK(...) ;

#define GUPFASTPRINTK(...) ;
#define DSMRETRYPRINTK(...) ;
//#define NOTIFYCHAINPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* for register_cpu_notifier() */
#define NOTIFYCHAINPRINTK(...) ;

/* Super specific debugging */
#define VCPUTONIDPRINTK(...) ;
//#define VCPUTONIDPRINTK(...) printk(KERN_INFO __VA_ARGS__)

/* Not perf critical */
#define KVMINITRINTK(...) printk(KERN_INFO __VA_ARGS__)

/* GEST OS printks */
//#define GSMPBSPPRINTK(...) printk(KERN_INFO __VA_ARGS__)
#define GSMPBSPPRINTK(...) ; // for gust smp bp //many
//#define GSMPPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* for guest smp */
#define GSMPPRINTK(...) ; // for guest smp
//#define GBSPIPIPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* for ipi in guest e.g. do_nothing(), kick_all_cpus_sync(), smp_call_function_single(), smp_call_function_many() */
#define GBSPIPIPRINTK(...) ;
#define GSMPIPIRESCHEDPRINTK(...) printk(KERN_INFO __VA_ARGS__) /* for ipi-resched in guest */
//#define GSMPIPIRESCHEDPRINTK(...) ; /* for ipi-resched in guest */
#endif /* end POP_CLEAN */

#define DEBUG_VMDSM_TRACE_SKIP_STACK 1
#define HYPE_VMCALL_DEBUG 0
#define ENFORCE_TOUCH_USR 0
#define ENFORCE_TOUCH_KERN 0
#define ENFORCE_TOUCH_BYTES 10

#define RETRY_FIRST_EPT 1 /* don't go to 2nd __gfn_to_pfn_memslot() / hva_to_pfn() */
#define DISABLE_WRITABLE_EPT 1 /* in hva_to_pfn_slow() virt/kvm/kvm_main.c */
#define DISABLE_VANILLA_DIRECT_PTE_PREFETCH 1 /* disable vanilla's direct_ept_prefetch in __direct_map() arch/x86/kvm/mmu.c */
/* Also check page_server.c HYPE_RETRY */

#define CONFIG_POPCORN_TERMINAL_MIGRATION 1

/* Debug */
#define DEBUG_PREFETCH_EPT 0

/* Hack */
#define HACK_GUEST_DS_ES_GS_AT_ORIGIN 0 /* doesn't affect */
#define HACK_GUEST_EFER 0 /* affected but not helpful */

/* Parameters */
#define HOST_X86_UART 3
#define GUEST_X86_UART 4
#define GUEST_X86_NET 25 /* aka PCN-IN */
#define VM_SINGLE_HANDLE_DISPLAY_CNT 100 /* large = slow */

/*************************************************************************/

/* guesos debugging points */
//typedef
enum {
	HYPE_DEBUG_POINT0,
	HYPE_DEBUG_POINT1,
	HYPE_DEBUG_POINT2,
	HYPE_DEBUG_POINT3,
	HYPE_DEBUG_POINT4,
	HYPE_DEBUG_POINT5,
	HYPE_DEBUG_POINT6,
	HYPE_DEBUG_POINT7,
	HYPE_DEBUG_POINT8,
	HYPE_DEBUG_POINT9,
	HYPE_DEBUG_POINT10,
	HYPE_DEBUG_POINT_MAX,
};

#define INTERESTED_GVA_LOW  0x1a00
#define INTERESTED_GVA_HIGH 0x1d00

#define INTERESTED_GVA_6LOW  0xec1a00
#define INTERESTED_GVA_6HIGH 0xec1d00
#define INTERESTED_4_BITS 0xffff
#define INTERESTED_6_BITS 0xffffff
#define INTERESTED_GVA_MASK(gva) (((gva) >> PAGE_SHIFT) & INTERESTED_4_BITS)
#define INTERESTED_GFN_MASK(gfn) (((gfn) >> 0) & INTERESTED_4_BITS)
#define INTERESTED_GVA_6MASK(gva) (((gva) >> PAGE_SHIFT) & INTERESTED_6_BITS)
#define INTERESTED_GFN_6MASK(gfn) (((gfn) >> 0) & INTERESTED_6_BITS)

#define INTERESTED_2AFTER4_BITS 0xffff00
#define INTERESTED_GVA_2AFTER4MASK(gva) (((gva) >> PAGE_SHIFT) & INTERESTED_2AFTER4_BITS)
#define INTERESTED_GFN_2AFTER4MASK(gfn) (((gfn) >> 0) & INTERESTED_2AFTER4_BITS)

#if INTERESTED_ADDRS
/* For SMP */
//#define NOTINTERESTED_GVA(gva) ( 1 ) /* afftected btw cnt */
#define NOTINTERESTED_GVA(gva) ( 0 ) /* not affected btw cnt */
#define NOTINTERESTED_GFN(gfn) ( 1 )
#define INTERESTED_GFN_2AFTER4(gfn) ( 0 )
#define INTERESTED_GVA_2AFTER4(gva) ( 0 )

/* For mount_root() */
#define INTERESTED_GVA(gva) ( 0 )
#define INTERESTED_GFN(gfn) ( 0 )

#else // !INTERESTED_ADDRS
#define INTERESTED_GVA(gva) 0
#define INTERESTED_GFN(gfn) 0
#define NOTINTERESTED_GVA(gva) 0
#endif

#endif /*  __INCLUDE_POPCORN_DEBUG_H__ */
