/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Very simple bitops for the boot code.
 */

#ifndef BOOT_BITOPS_H
#define BOOT_BITOPS_H
#define _LINUX_BITOPS_H		/* Inhibit inclusion of <linux/bitops.h> */

#ifdef CONFIG_POPCORN_HYPE
////#include <popcorn/bundle.h>
//#include <popcorn/debug.h>
#endif

static inline int constant_test_bit(int nr, const void *addr)
{
	const u32 *p = (const u32 *)addr;
//#ifdef CONFIG_POPCORN_HYPE
//#if !POPHYPE_HOST_KERNEL
//	GSMPBSPPRINTK("\t<%d> %s():\n", smp_processor_id(), __func__);
//#endif
//#endif
	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}
static inline int variable_test_bit(int nr, const void *addr)
{
	u8 v;
	const u32 *p = (const u32 *)addr;
//#ifdef CONFIG_POPCORN_HYPE
//#if !POPHYPE_HOST_KERNEL
//	GSMPBSPPRINTK("\t<%d> %s():\n", smp_processor_id(), __func__);
//#endif
//#endif

	asm("btl %2,%1; setc %0" : "=qm" (v) : "m" (*p), "Ir" (nr));
	return v;
}

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))

static inline void set_bit(int nr, void *addr)
{
	asm("btsl %1,%0" : "+m" (*(u32 *)addr) : "Ir" (nr));
}

#endif /* BOOT_BITOPS_H */
