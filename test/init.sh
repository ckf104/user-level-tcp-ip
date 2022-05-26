#! /bin/sh

export LD_LIBRARY_PATH=../src/build
cd ../helper
./addNS ns1
./addNS ns2
./connectNS ns1 ns2 v1 v2 10.100.1
./execNS ns1 tc qdisc add dev v1 root netem delay 1s reorder 10% loss 10%
./execNS ns2 tc qdisc add dev v2 root netem delay 1s reorder 10% loss 10%
./execNS ns1 ./bypassKernel


