#!/bin/bash

set -x
set -e

test_ns=l3tc_

function create_fresh_netns() {
    local name=$test_ns$1
    local match=$(ip netns list | grep "^$name\$")
    if [ "x$match" != "x" ]; then
        ip netns del $name
    fi
    ip netns add $name
}

for n in $(echo sw red green blue); do
    create_fresh_netns $n
done

function e() {
    ip netns exec $test_ns$*
}

e sw ip link add r0 type veth peer name r1
e sw ip link add g0 type veth peer name g1
e sw ip link add b0 type veth peer name b1
e sw ip link set r1 netns ${test_ns}red
e sw ip link set g1 netns ${test_ns}green
e sw ip link set b1 netns ${test_ns}blue

e sw brctl addbr rgb
e sw brctl addif rgb r0
e sw brctl addif rgb g0
e sw brctl addif rgb b0

e sw ip link set rgb up
e sw ip link set r0 up
e sw ip link set g0 up
e sw ip link set b0 up

red_ip=192.168.10.1
e red ip link set r1 up
e red ip addr add $red_ip/28 dev r1

green_ip=192.168.10.2
e green ip link set g1 up
e green ip addr add $green_ip/28 dev g1

blue_ip=192.168.10.3
e blue ip link set b1 up
e blue ip addr add $blue_ip/28 dev b1

# ensure everyone can talk to everyone else, for now
e red ping -c 1 $green_ip
e red ping -c 1 $blue_ip
e green ping -c 1 $blue_ip
e green ping -c 1 $red_ip
e blue ping -c 1 $red_ip
e blue ping -c 1 $green_ip

tmp_dir=$(readlink -f test.tmp)
mkdir -p $tmp_dir
peer_file=$tmp_dir/peers

echo "$red_ip
$green_ip
$blue_ip" > $peer_file

ulimit -c unlimited

e red valgrind --leak-check=full ../src/l3tc -d -d -p $peer_file -4 $red_ip -c 0 -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/red.log 2>&1 &
red_pid=$!
e green valgrind --leak-check=full ../src/l3tc -d -d -p $peer_file -4 $green_ip -c 0 -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/green.log 2>&1 &
green_pid=$!
e blue valgrind --leak-check=full ../src/l3tc -d -d -p $peer_file -4 $blue_ip -c 0 -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/blue.log 2>&1 &
blue_pid=$!

e red ping -c 1 $green_ip
e red ping -c 1 $blue_ip
e green ping -c 1 $blue_ip
e green ping -c 1 $red_ip
e blue ping -c 1 $red_ip
e blue ping -c 1 $green_ip

kill -TERM $red_pid $green_pid $blue_pid

wait $red_pid && echo "Red came clean"
wait $green_pid  && echo "Green came clean"
wait $blue_pid && echo "Blue came clean"
