#!/bin/bash 

rm -rf ./patches > /dev/null 2>&1 
mkdir patches 

SYZ_DIR="../syzkaller"
DIRS="syz-fuzzer syz-manager executor pkg prog" 

for DIR in $DIRS
do
	diff -NrbBpu $SYZ_DIR/$DIR  ./$DIR > patches/$DIR.patch
done

