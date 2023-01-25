#! /bin/sh
#
# xxx.sh
# Copyright (C) 2018 jackchuang <jackchuang@echo5>
#
# Distributed under terms of the MIT license.
#

CPUS=`lscpu |grep CPU\(s\): |sed 's/CPU.* //g'`
echo "$CPUS cpus on this machine"
make -j$CPUS && make modules -j$CPUS && sudo make modules_install && sudo make install
