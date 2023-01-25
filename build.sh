#!/bin/bash

echo -e "\n\nTHIS FILE IS FROM MIR* OR MIR\n\n"
echo "0: skip \$make"
echo "Input counts: $#"
echo "First arg: $1"
if [ "$1" = "0" ];
then
    echo "skiped \$make"
else
    echo "make -j32"
	make -j32
fi

KERNEL_PATH=~/kh
echo "restore #define POPHYPE_HOST_KERNEL 1 in $KERNEL_PATH/include/popcorn/debug.h"
sed -i 's/#define POPHYPE_HOST_KERNEL 0/#define POPHYPE_HOST_KERNEL 1/g' $KERNEL_PATH/include/popcorn/debug.h

make -j32 -C msg_layer
ret=$?
if [[ $ret != 0 ]]; then
	exit -1
fi
make modules -j32 && \
sudo make modules_install && \
sudo make install

#echo "\n\n\n\n\n\n"
#sudo make modules_install -j32 -C /home/jackchuang/share/popcorn-rack

#echo "\n\n\n\n\n\n"
#sudo make install -C /home/jackchuang/share/popcorn-rack
#sudo grub-set-default 1

#ssh echo5 "make -C /mnt/popcorn-rack -j99"
#ssh echo5 "sudo make modules_install -j99"
#for i in {5..6..1}
#do
#	ssh echo$i "sudo make install -C /mnt/popcorn-rack"
#	ssh echo$i "sudo reboot"
#
#    for j in {1..10..1}
#    do
#        echo "done on echo$i"
#    done
#
#	sleep 5
#	sudo ipmitool -I lanplus -H ipmi$i -U ADMIN -P ADMIN chassis power cycle
#done
ret=$?
exit $ret
