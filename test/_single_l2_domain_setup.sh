#!/bin/bash

set -e

shopt -s expand_aliases

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
        set +e
        sudo ip netns pid $name | grep -q .
        has_processes=$?
        set -e
        if [ "x$has_processes" == "x0" ]; then
            sudo ip netns pid $name | xargs sudo ip netns exec $name kill -9 
        fi
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

red_launch_pid_file=$tmp_dir/red_launch.pid
green_launch_pid_file=$tmp_dir/green_launch.pid
blue_launch_pid_file=$tmp_dir/blue_launch.pid

function capture_launch_pid {
    local launch_pid=$!
    echo -n $launch_pid > $1
}

log_frag=${log_severity_frag:-" "}
opts=${additional_opts:-"-L 1"}
comp_lvl=${compression_level:-1}

alias start_red="e red $cmd_prefix ../src/l3tc $opts $log_frag -p $peer_file -4 $red_ip -P $red_pid_file -c $comp_lvl -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/red.log 2>&1 &"
alias start_green="e green $cmd_prefix ../src/l3tc $opts $log_frag -p $peer_file -4 $green_ip -P $green_pid_file -c $comp_lvl -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/green.log 2>&1 &"
alias start_blue="e blue $cmd_prefix ../src/l3tc $opts $log_frag -p $peer_file -4 $blue_ip -P $blue_pid_file -c $comp_lvl -r 1 -u ../scripts/l3tc_routeup.sh >$tmp_dir/blue.log 2>&1 &"
function launch_red {
    start_red
    capture_launch_pid $red_launch_pid_file
}
function launch_green {
    start_green
    capture_launch_pid $green_launch_pid_file
}
function launch_blue {
    start_blue
    capture_launch_pid $blue_launch_pid_file
}

alias kill_red="e red pkill -F $red_pid_file"
alias kill_green="e red pkill -F $green_pid_file"
alias kill_blue="e red pkill -F $blue_pid_file"

function await_red {
    wait $(cat $red_launch_pid_file) && echo 'Red came clean'
}
function await_green {
    wait $(cat $green_launch_pid_file) && echo 'Green came clean'
}
function await_blue {
    wait $(cat $blue_launch_pid_file) && echo 'Blue came clean'
}

launch_red
launch_green
launch_blue

function await_red_l3tc_up {
    while [ $(e red netstat -antl | grep :15 | grep ESTABLISHED | wc -l) != 2 ]; do
        sleep .2
    done
}

function await_green_l3tc_up {
    while [ $(e green netstat -antl | grep :15 | grep ESTABLISHED | wc -l) != 2 ]; do
        sleep .2
    done
}

await_red_l3tc_up
await_green_l3tc_up

function l3tc_cleanup {
    kill_red
    kill_green
    kill_blue

    await_red
    await_green
    await_blue
}

trap l3tc_cleanup EXIT

