#! /bin/bash
#
# auto_apply_git.sh
# Copyright (C) 2018 jackchuang <jackchuang@echo5>
#
# Distributed under terms of the MIT license.
#

echo "Script: applying git patch \"$1\" and modify corresponding things"
#check file
#if [[ $1 -f ]]

#t
echo "buffer msg_layer/config.h"
cp msg_layer/config.h tmp

echo "applying git patch \"$1\""
git reset --hard HEAD
git apply msg_dsm_latencies_v4.patch

echo "replace msg_layer/config.h"
cp tmp msg_layer/config.h
rm tmp
#make oldconfig

echo "TODO: double check for make menuconfig"

echo "TODO: ./build.sh"
#./build.sh


# 1924  make menuconfig
# 1925  make -j33
# 1926  make modules -j44
# 1927  sudo make modules_install && sudo make
# 1928  sudo make modules_install && sudo make install
