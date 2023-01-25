#! /bin/bash
#
# sync.sh
# Copyright (C) 2021 Karim Manaouil <karim.manaouil@ed.ac.uk>
#
# Distributed under terms of the MIT license.
#

KERNEL="kh_tong"
FILES=`git status | grep modified | cut -d":" -f2 | uniq | xargs`
FILES=(${FILES[@]} $1)

for file in ${FILES[@]}; do
	for node in echo4 echo1 echo0; do
		rsync -a "/home/jackchuang/$KERNEL/$file" \
				$node:"/home/jackchuang/$KERNEL/$file"
		echo "$file synched on $node"
	done
done


