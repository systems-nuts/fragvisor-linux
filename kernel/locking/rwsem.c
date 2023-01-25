/* kernel/rwsem.c: R/W semaphores, public implementation
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from asm-i386/semaphore.h
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/export.h>
#include <linux/rwsem.h>
#include <linux/atomic.h>

#include "rwsem.h"

#ifdef CONFIG_POPCORN
#include <popcorn/types.h>
#include <popcorn/debug.h>
#endif
/*
 * lock for reading
 */
void __sched down_read(struct rw_semaphore *sem)
{
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long down_read_cnt = 0;
	unsigned long limit_down_read_cnt = 0;
	if (distributed_process(current) &&
		!(_RET_IP_ > 0xffffffff81450000) &&
		_RET_IP_ != 0xffffffff81450a61 &&
		_RET_IP_ != 0xffffffff81450b61 &&
		_RET_IP_ != 0xffffffff81456dfa &&
		_RET_IP_ != 0xffffffff81456f0a) {
		down_read_cnt++;
		if (current->at_remote) {
			//limit_down_read_cnt = 1048500; /* trying to find a good value */
			//limit_down_read_cnt = 948500;
			limit_down_read_cnt = 0; // 1xxxxx
		} else {
			//limit_down_read_cnt = 1048655;
			//limit_down_read_cnt = 40000; // 4xxxxx
			limit_down_read_cnt = 47000; // 47491
		}
		if (down_read_cnt > limit_down_read_cnt ||
			!(down_read_cnt % 10000) // testing
			) {
			LKPRINTK("lk: [%d] LOCK %p %lx #%lu\n",
					current->pid, sem, //(void *)&sem->dep_map,
					_RET_IP_, down_read_cnt);
		}
	}
#endif
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, 0, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}

EXPORT_SYMBOL(down_read);

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int down_read_trylock(struct rw_semaphore *sem)
{
	int ret = __down_read_trylock(sem);
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long try_down_read_cnt = 0;
	unsigned long limit_try_down_read_cnt = 0;
#endif

	if (ret == 1) {
#ifdef CONFIG_POPCORN_HYPE
		if (distributed_process(current) &&
			!(_RET_IP_ > 0xffffffff81450000) &&
			_RET_IP_ != 0xffffffff81450a61 && // 5tty
			_RET_IP_ != 0xffffffff81450b61 && // 5tty
			_RET_IP_ != 0xffffffff81456dfa && // 4tty
			_RET_IP_ != 0xffffffff81456f0a) { // 4tty
			try_down_read_cnt++;
			if (current->at_remote) {
				limit_try_down_read_cnt = 1048500;
			} else {
				//limit_try_down_read_cnt = 1048655;
				//limit_try_down_read_cnt = 1053413;
				//limit_try_down_read_cnt = 1093181;
				limit_try_down_read_cnt = 1094616;
			}
			if (try_down_read_cnt > limit_try_down_read_cnt) {
				LKPRINTK("lk: [%d] try succ LOCK %p %lx #%lu\n",
						current->pid, sem, //(void *)&sem->dep_map,
									_RET_IP_, try_down_read_cnt);
			}
		}
#endif
		rwsem_acquire_read(&sem->dep_map, 0, 1, _RET_IP_);
	}
	return ret;
}

EXPORT_SYMBOL(down_read_trylock);

/*
 * lock for writing
 */
void __sched down_write(struct rw_semaphore *sem)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, 0, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
	rwsem_set_owner(sem);
}

EXPORT_SYMBOL(down_write);

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int down_write_trylock(struct rw_semaphore *sem)
{
	int ret = __down_write_trylock(sem);

	if (ret == 1) {
		rwsem_acquire(&sem->dep_map, 0, 1, _RET_IP_);
		rwsem_set_owner(sem);
	}

	return ret;
}

EXPORT_SYMBOL(down_write_trylock);

/*
 * release a read lock
 */
void up_read(struct rw_semaphore *sem)
{
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long up_read_cnt = 0;
	unsigned long limit_up_read_cnt = 0;
	if (distributed_process(current) &&
		!(_RET_IP_ > 0xffffffff81450000) &&
		_RET_IP_ != 0xffffffff81450a61 &&
		_RET_IP_ != 0xffffffff81450b61 &&
		_RET_IP_ != 0xffffffff81456dfa &&
		_RET_IP_ != 0xffffffff81456f0a) {
		up_read_cnt++;
		if (current->at_remote) {
			limit_up_read_cnt = 1048646;
		} else {
			//limit_up_read_cnt = 1048747;
			//limit_up_read_cnt = 1145400;
			//limit_up_read_cnt = 1125666;
			limit_up_read_cnt = 1140503; // good to see origin kernel log and other logs
			//limit_up_read_cnt = 1142400; // good to see origin kernel log
			//limit_up_read_cnt = 1151800; // start from sipi
		}
		if (up_read_cnt > limit_up_read_cnt) {
			LKPRINTK("lk: [%d] UNLOCK %p %s%lx%s #%lu\n",
				current->pid, sem, //(void *)&sem->dep_map,
				/* 0xffffffff810ad239 try succ LOCK origin */
				_RET_IP_ == 0xffffffff810ad239 || _RET_IP_ == 0xffffffff810ad2e3 ?
					"$$[[[" : "",
				_RET_IP_,
				_RET_IP_ == 0xffffffff810ad239 || _RET_IP_ == 0xffffffff810ad2e3?
					"]]]" : "",
				up_read_cnt);
		}
		//if (up_read_cnt > 1153750 && up_read_cnt < 1153950)
		//	dump_stack();
	}
#endif
	rwsem_release(&sem->dep_map, 1, _RET_IP_);

	__up_read(sem);
}

EXPORT_SYMBOL(up_read);

/*
 * release a write lock
 */
void up_write(struct rw_semaphore *sem)
{
	rwsem_release(&sem->dep_map, 1, _RET_IP_);

	rwsem_clear_owner(sem);
	__up_write(sem);
}

EXPORT_SYMBOL(up_write);

/*
 * downgrade write lock to read lock
 */
void downgrade_write(struct rw_semaphore *sem)
{
	/*
	 * lockdep: a downgraded write will live on as a write
	 * dependency.
	 */
	rwsem_clear_owner(sem);
	__downgrade_write(sem);
}

EXPORT_SYMBOL(downgrade_write);

#ifdef CONFIG_DEBUG_LOCK_ALLOC

void down_read_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire_read(&sem->dep_map, subclass, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_read_trylock, __down_read);
}

EXPORT_SYMBOL(down_read_nested);

void _down_write_nest_lock(struct rw_semaphore *sem, struct lockdep_map *nest)
{
	might_sleep();
	rwsem_acquire_nest(&sem->dep_map, 0, 0, nest, _RET_IP_);

	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
	rwsem_set_owner(sem);
}

EXPORT_SYMBOL(_down_write_nest_lock);

void down_read_non_owner(struct rw_semaphore *sem)
{
	might_sleep();

	__down_read(sem);
}

EXPORT_SYMBOL(down_read_non_owner);

void down_write_nested(struct rw_semaphore *sem, int subclass)
{
	might_sleep();
	rwsem_acquire(&sem->dep_map, subclass, 0, _RET_IP_);

	LOCK_CONTENDED(sem, __down_write_trylock, __down_write);
	rwsem_set_owner(sem);
}

EXPORT_SYMBOL(down_write_nested);

void up_read_non_owner(struct rw_semaphore *sem)
{
	__up_read(sem);
}

EXPORT_SYMBOL(up_read_non_owner);

#endif


