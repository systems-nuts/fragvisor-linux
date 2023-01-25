#undef TRACE_SYSTEM
#define TRACE_SYSTEM popcorn

#if !defined(_TRACE_EVENTS_POPCORN_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EVENTS_POPCORN_H_

#include <linux/tracepoint.h>


TRACE_EVENT(pgfault,
	TP_PROTO(const int nid, const int pid, const char rw,
		const unsigned long instr_addr, const unsigned long addr,
		const int result),

	TP_ARGS(nid, pid, rw, instr_addr, addr, result),

	TP_STRUCT__entry(
		__field(int, nid)
		__field(int, pid)
		__field(char, rw)
		__field(unsigned long, instr_addr)
		__field(unsigned long, addr)
		__field(int, result)
	),

	TP_fast_assign(
		__entry->nid = nid;
		__entry->pid = pid;
		__entry->rw = rw;
		__entry->instr_addr = instr_addr;
		__entry->addr = addr;
		__entry->result = result;
	),

	TP_printk("%d %d %c %lx %lx %d",
		__entry->nid, __entry->pid, __entry->rw,
		__entry->instr_addr, __entry->addr, __entry->result)
);


TRACE_EVENT(pgfault_stat,
	TP_PROTO(const unsigned long instr_addr, const unsigned long addr,
		const int result, const int retries, const unsigned long time_ns),

	TP_ARGS(instr_addr, addr, result, retries, time_ns),

	TP_STRUCT__entry(
		__field(unsigned long, instr_addr)
		__field(unsigned long, addr)
		__field(int, result)
		__field(int, retries)
		__field(unsigned long, time_ns)
	),

	TP_fast_assign(
		__entry->instr_addr = instr_addr;
		__entry->addr = addr;
		__entry->result = result;
		__entry->retries = retries;
		__entry->time_ns = time_ns;
	),

	TP_printk("%lx %lx %d %d %lu",
		__entry->instr_addr, __entry->addr, __entry->result,
		__entry->retries, __entry->time_ns)
);

/*
typedef struct {
    unsigned long addr;
    unsigned long rip;
    unsigned long rbp;
    unsigned long rsp;
    unsigned long stack[MAX_VM_STACK_DEBUG];
    unsigned long cnt;
    unsigned long long time;
} dsm_traffic_t;
*/
/*
 *	address: full
 *	addr: page addr
 */
TRACE_EVENT(vmdsm_traffic,
	TP_PROTO(const unsigned long addr, const char rw,
		const unsigned long rip, const unsigned long rbp,
		const unsigned long rsp, const unsigned long stack0,
		const unsigned long stack1, const unsigned long stack2,
		const unsigned long stack3, const unsigned long stack4,
		const unsigned long address, const int kvm_mp_state,
		const unsigned long ns, const int vcpu_cpl,
		const int vcpu_mode, const unsigned long api_rip,
		unsigned long real_gva, unsigned long exit_qualification),

	TP_ARGS(addr, rw, rip, rbp, rsp,
			stack0, stack1, stack2, stack3, stack4,
				address, kvm_mp_state, ns,
				vcpu_cpl, vcpu_mode, api_rip,
				real_gva, exit_qualification),

	TP_STRUCT__entry(
		__field(unsigned long, addr)
		__field(char, rw)
		__field(unsigned long, rip)
		__field(unsigned long, rbp)
		__field(unsigned long, rsp)
		__field(unsigned long, stack0)
		__field(unsigned long, stack1)
		__field(unsigned long, stack2)
		__field(unsigned long, stack3)
		__field(unsigned long, stack4)
		__field(unsigned long, address)
		__field(int, kvm_mp_state)
		__field(unsigned long, ns)
		__field(int, vcpu_cpl)
		__field(int, vcpu_mode)
		__field(unsigned long, api_rip)
		__field(unsigned long, real_gva)
		__field(unsigned long, exit_qualification)
	),

	TP_fast_assign(
		__entry->addr = addr; /* cr2 >> PAGE_SHIFT */
		__entry->rw = rw;
		__entry->rip = rip;
		__entry->rbp = rbp;
		__entry->rsp = rsp;
		__entry->stack0 = stack0;
		__entry->stack1 = stack1;
		__entry->stack2 = stack2;
		__entry->stack3 = stack3;
		__entry->stack4 = stack4;
		__entry->address = address; /* cr2 */
		__entry->kvm_mp_state = kvm_mp_state;
		__entry->ns = ns;
		__entry->vcpu_cpl = vcpu_cpl;
		__entry->vcpu_mode = vcpu_mode;
		__entry->api_rip = api_rip;
		__entry->real_gva = real_gva;
		__entry->exit_qualification = exit_qualification;
		),

	TP_printk("%lx %c %lx %lx %lx %lx %lx %lx %lx %lx %lx %d %lu - %d %d %lx - %lx %lx (%c%c%c %c%c%c%c %c%c %s%s)",
		__entry->addr, __entry->rw, __entry->rip, __entry->rbp,
		__entry->rsp, __entry->stack0, __entry->stack1,
		__entry->stack2, __entry->stack3, __entry->stack4,
		__entry->address, __entry->kvm_mp_state, __entry->ns,
		__entry->vcpu_mode, __entry->vcpu_mode, __entry->api_rip,
		__entry->real_gva,
		__entry->exit_qualification,
		((__entry->exit_qualification & 0x1) ? 'r' : '-'),
		((__entry->exit_qualification & 0x2) ? 'w' : '-'),
		((__entry->exit_qualification & 0x4) ? 'f' : '-'),
		((__entry->exit_qualification & 0x8) ? 'R' : '-'),
		((__entry->exit_qualification & 0x10) ? 'W' : '-'),
		((__entry->exit_qualification & 0x20) ? 'X' : '-'),
		((__entry->exit_qualification & 0x40) ? 'x' : '-'),
		((__entry->exit_qualification & 0x80) ? ((__entry->exit_qualification & 0x100) ? 'p' : 't') : '-'), // last or walks
		((__entry->exit_qualification & 0x80) && (__entry->exit_qualification & 0x100) ? ((__entry->exit_qualification & 0x200) ? 'u' : 'k') : '-'),
		((__entry->exit_qualification & 0x80) && (__entry->exit_qualification & 0x100) ? ((__entry->exit_qualification & 0x400) ? "ro" : "rw") : "-"),
		((__entry->exit_qualification & 0x80) && (__entry->exit_qualification & 0x100) ? ((__entry->exit_qualification & 0x800) ? "Ex" : "Nx") : "-")
		)
);


/*
 * Retry before __direct_map() in ./arch/x86/kvm/mmu.c.
 */
TRACE_EVENT(kvm_ept_retry,
    TP_PROTO(unsigned long fast_retry_gpa, unsigned long retry_gpa, unsigned long inv_gpa),
    TP_ARGS(fast_retry_gpa, retry_gpa, inv_gpa),

    TP_STRUCT__entry(
        __field(    unsigned long,  fast_retry_gpa   )
        __field(    unsigned long,  retry_gpa   )
        __field(    unsigned long,  inv_gpa )
    ),

    TP_fast_assign(
        __entry->fast_retry_gpa  = fast_retry_gpa;
        __entry->retry_gpa  = retry_gpa;
        __entry->inv_gpa    = inv_gpa;
    ),

    TP_printk("fast_retry_gpa %lx retry_gpa %lx inv_gpa %lx",
          __entry->fast_retry_gpa,
          __entry->retry_gpa,
          __entry->inv_gpa)
);
#endif

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE

#define TRACE_INCLUDE_PATH ../../kernel/popcorn
#define TRACE_INCLUDE_FILE trace_events
#include <trace/define_trace.h>
