/*
 * hype.h
 * Copyright (C) 2019 jackchuang <jackchuang@mir7>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef HYPE_H
#define HYPE_H
#include <../kernel/popcorn/types.h>
#include <../kernel/popcorn/wait_station.h>

#include <popcorn/debug.h>
//#include <popcorn/hype_file.h>

#define POPHYPE_PRIVATE_TSS 1 /* anon pg's pgoff = 0 */


/* VM_EXIT negative to return to userspace */
#define KVM_RET_POPHYPE_MIGRATE -78



#endif /* !HYPE_H */
