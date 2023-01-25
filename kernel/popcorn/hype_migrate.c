/*
 * hype_migrate.c
 * Copyright (C) 2020 jackchuang <jackchuang@mir>
 *
 * Distributed under terms of the MIT license.
 *
 * @author Ho-Ren (Jack) Chuang, SSRG Virginia Tech 2020
 */

//#include <popcorn/hype_migrate.h> // cannot compile. why?
#include <linux/kvm_host.h>

#include <linux/kernel.h> /* syscall*/
#include <linux/syscalls.h> /* syscall */
#include <linux/delay.h> /* msleep */

#include <linux/module.h>
#include <linux/moduleparam.h>


#ifdef CONFIG_POPCORN_HYPE

/* search EXIT_REASON_VMCALL & handle_vmcall in ./arch/x86/kvm/vmx.c
 *		 handle_vmcall -> kvm_emulate_hypercall
 * ref: https://www.vvzixun.com/index.php/code/2cd8231a84b405b7b5cc5b3df7dad6be
 *
 * VM kvm_hypercall*(nr, argv0, argv1, ...);
 * nr: reason
 * a0: argv0
 * a1: argv1
 * example: kvm_hypercall2(KVM_HC_KICK_CPU, flags, apicid);
 * 									in ./arch/x86/kernel/kvm.c
 *	--------------------------------
 * Host  kvm_emulate_hypercall()
 * nr: reason
 * a0: argv0
 * a1: argv1
 *		(...)
 * case KVM_HC_KICK_CPU:
 */

//#if !POPHYPE_HOST_KERNEL /* TODO: fix it: compiler error "undefined reference to `sys_pophype_migrate'" */
/* syscall -> hypercall (guest) -> user lkvm calls migrate(0) + init vcpu + migration(1) + migration(87) pophype_do_migrate() to update states and then migrate(0)
 *
 */
//SYSCALL_DEFINE1(pophype_migrate, int __user, a0, int, a1)
SYSCALL_DEFINE2(pophype_migrate, int, a0, int, a1)
{
	PHGMIGRATEPRINTK("[%d] <%d> %s %d %s(): Start\n",
					current->pid, smp_processor_id(), __FILE__, __LINE__, __func__);
	kvm_hypercall2(KVM_HC_POPHYPE_MIGRATE, a0, a1);
	PHGMIGRATEPRINTK("[%d] <%d> %s %d %s(): Done for debugging and see this printk (GO HOME!!!!!!!!)\n",
					current->pid, smp_processor_id(), __FILE__, __LINE__, __func__);
	return 0;
}
//#endif


//kvm_hypercall2(KVM_HC_POPHYPE_NET_DELEGATE. a0, a1);

/* pophype migration request from host kernel */
// oeigin: to/back
//
int pophype_puase_vm_and_migrate(void)
{
	// 1 kick with reason
	//		kvm_vcpu_kick(vcpu)
	// 2 check the reason
	// 3 call the pophype migration
	return 0;
}

#if 0
/* Idea: This has to be in user:
 * hypercall -> return to user with vm_exit=xxx
 *	(user) syscall pophype_migration_flag on
 * 	(user) syscall flush_dsm (when should I do this) (search destroy rc)
 * 	(user) syscall migration (rely on pophype_migration_flag to know it should do optimized migration)
 *	(user) syscall pophype_migration_flag off
 * 	(user)
 *
 */
/* pophype migration request from guest VM */
#endif

#endif
