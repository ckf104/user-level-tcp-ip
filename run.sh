#! /bin/sh

if [ "$1"x = 'rm'x ] 
then
	cd checkpoints && rm echo_server echo_client perf_server perf_client
	ip netns del ns1
	ip netns del ns2
	ip netns del ns3
	ip netns del ns4
	exit 0
fi
ulimit -c unlimited

cd helper
./addNS ns1
./addNS ns2
./addNS ns3
./addNS ns4

./connectNS ns1 ns2 v1 v2 10.100.1
./connectNS ns2 ns3 v3 v4 10.100.2
./connectNS ns3 ns4 v5 v6 10.100.3

cd ../checkpoints && make CFLAGS="-g -Wl,--wrap,close -Wl,--wrap,socket -Wl,--wrap,listen -Wl,--wrap,bind -Wl,--wrap,connect -Wl,--wrap,getaddrinfo -Wl,--wrap,freeaddrinfo -Wl,--wrap,write -Wl,--wrap,accept -Wl,--wrap,read -Wl,--wrap,setsockopt -L../src/build -lsrc"

cd ../helper
./execNS ns1 ./bypassKernel
./execNS ns2 ./bypassKernel
./execNS ns3 ./bypassKernel
./execNS ns4 ./bypassKernel

export LD_LIBRARY_PATH=../src/build 

if [ "$1"x = 'echo'x ]
then
	./execNS ns2 tc qdisc add dev v3 root netem loss 20%
	./execNS ns4 ../checkpoints/echo_server &
	./execNS ns2 ../test/router &
	./execNS ns3 ../test/router &
	./execNS ns1 ../checkpoints/echo_client 10.100.3.2
	wait $(ps aux | grep '[_]server' | awk '{print $2}')

elif [ "$1"x = 'perf'x ]
then
	./execNS ns4 ../checkpoints/perf_server &
	./execNS ns2 ../test/router &
	./execNS ns3 ../test/router &
	./execNS ns1 ../checkpoints/perf_client 10.100.3.2
	wait $(ps aux | grep '[_]server' | awk '{print $2}')
fi

kill -9 $(ps aux | grep '[r]outer' | awk '{print $2}')


./delNS ns1
./delNS ns2
./delNS ns3
./delNS ns4
