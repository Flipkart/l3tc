#!/bin/bash

test_ns=l3tc_
sudo_bin=$(which sudo)

if [ "x$sudo_bin" == "x" ]; then
    echo "Can't find 'sudo', aborting integration-test."
    exit 1
fi

function sudo {
    echo "[SUDO] Running sudo command: $*" >&2
    $sudo_bin $*
}

function create_fresh_netns {
    local name=$test_ns$1
    local match=$(ip netns list | grep "^$name\$")
    if [ "x$match" != "x" ]; then
        sudo ip netns del $name
    fi
    sudo ip netns add $name
}

for n in $(echo sw red green blue); do
    create_fresh_netns $n
done

function e {
    sudo ip netns exec $test_ns$*
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

e red sysctl -w net.ipv4.conf.all.rp_filter=0
e red sysctl -w net.ipv4.conf.default.rp_filter=0
e green sysctl -w net.ipv4.conf.all.rp_filter=0
e green sysctl -w net.ipv4.conf.default.rp_filter=0
e blue sysctl -w net.ipv4.conf.all.rp_filter=0
e blue sysctl -w net.ipv4.conf.default.rp_filter=0

tmp_dir=$(readlink -f test.tmp)
mkdir -p $tmp_dir
peer_file=$tmp_dir/peers

echo "$red_ip
$green_ip
$blue_ip" > $peer_file

ulimit -c unlimited

cmd_prefix="valgrind --leak-check=full"
cmd_prefix=""

red_pid_file=$tmp_dir/red.pid
green_pid_file=$tmp_dir/green.pid
blue_pid_file=$tmp_dir/blue.pid

e red $cmd_prefix ../src/l3tc -L 1 -d -d -p $peer_file -4 $red_ip -P $red_pid_file -c 0 -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/red.log 2>&1 &
red_pid=$!
e green $cmd_prefix ../src/l3tc -L 1 -d -d -p $peer_file -4 $green_ip -P $green_pid_file -c 0 -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/green.log 2>&1 &
green_pid=$!
e blue $cmd_prefix ../src/l3tc -L 1 -d -d -p $peer_file -4 $blue_ip -P $blue_pid_file -c 0 -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/blue.log 2>&1 &
blue_pid=$!

while [ $(e red netstat -antl | grep :15 | grep ESTABLISHED | wc -l) != 2 ]; do
    sleep .2
done

while [ $(e green netstat -antl | grep :15 | grep ESTABLISHED | wc -l) != 2 ]; do
    sleep .2
done

function l3tc_cleanup {
    e red pkill -F $red_pid_file
    e green pkill -F $green_pid_file
    e blue pkill -F $blue_pid_file

    wait $red_pid && echo "Red came clean"
    wait $green_pid  && echo "Green came clean"
    wait $blue_pid && echo "Blue came clean"
}

trap l3tc_cleanup EXIT

