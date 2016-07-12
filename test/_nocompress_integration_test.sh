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

e red ip link set r1 up
e red ip addr add 192.168.10.1/28 dev r1

e green ip link set g1 up
e green ip addr add 192.168.10.2/28 dev g1

e blue ip link set b1 up
e blue ip addr add 192.168.10.3/28 dev b1

# ensure everyone can talk to everyone else, for now
e red ping -c 1 192.168.10.2
e red ping -c 1 192.168.10.3
e green ping -c 1 192.168.10.3
e green ping -c 1 192.168.10.1
e blue ping -c 1 192.168.10.1
e blue ping -c 1 192.168.10.2

