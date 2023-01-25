#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
#include <popcorn/types.h>
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long cnt = 0;
	//if (cnt > 100000)
	if (distributed_remote_process(current)) {
		if (cnt >= 0) {
			LKPRINTK("[%d] (down_write->)rwsem_set_owner cnt %ld #%lu\n", current->pid, sem->count, ++cnt);
		}
	}
#endif
	sem->owner = current;
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
#ifdef CONFIG_POPCORN_HYPE
	static unsigned long cnt = 0;
	//if (cnt > 100000)
	if (distributed_remote_process(current)) {
		if (cnt >= 0) {
			LKPRINTK("[%d] (up_write->)rwsem_clear_owner cnt %ld #%lu\n", current->pid, sem->count, ++cnt);
		}
	}
#endif
	sem->owner = NULL;
}

#else
static inline void rwsem_set_owner(struct rw_semaphore *sem)
{
}

static inline void rwsem_clear_owner(struct rw_semaphore *sem)
{
}
#endif
