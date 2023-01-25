/*
 * hype_files.h
 * Copyright (C) 2019 jackchuang <jackchuang@mir7>
 *
 * Distributed under terms of the MIT license.
 */

#ifndef HYPE_FILES_H
#define HYPE_FILES_H
#include <linux/types.h>
#include <linux/compiler.h>

//#include <linux/file.h>
//#include <linux/fsnotify.h>
//#include <linux/fdtable.h>
#include <linux/fs.h>
//#include <../fs/internal.h>

#include <linux/uaccess.h> // copy_from_user

#include <popcorn/types.h>
#include <popcorn/pcn_kmsg.h>

#include <../kernel/popcorn/types.h>
#include <../kernel/popcorn/wait_station.h>


int popcorn_open(const char __user *filename, int flags, umode_t mode, int fd);

#endif /* !HYPE_FILES_H */
