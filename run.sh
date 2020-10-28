# !/bin/bash

TIME="12h"

rm rtv52.json
rm ../syzkaller/rtv56.json

$(pwd)/bin/syz-manager -config=./v52.cfg -bench=rtv52.json > log.hangs 2>&1 &

sleep 1s
cd $(pwd)/../syzkaller
./bin/syz-manager -config=./v56.cfg -bench=rtv56.json > log.hangs 2>&1 &


sleep $TIME

pkill syz-manager
pkill syz-manager
