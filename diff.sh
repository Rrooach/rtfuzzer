#!/bin/bash 

rm -rf ./patch > /dev/null 2>&1 
mkdir patch 

SYZ_DIR="../syzkaller"
DIRS="syz-fuzzer syz-manager executor pkg prog" 

for DIR in $DIRS
do
	diff -NrbBpu $SYZ_DIR/$DIR  ./$DIR > patch/$DIR.patch
done

