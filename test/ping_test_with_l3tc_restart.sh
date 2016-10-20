#!/bin/bash

. _single_l2_domain_setup.sh

ping_pid_file=$tmp_dir/ping.pid

ping_summary_file=$tmp_dir/ping.summary

e red ./_fast_ping $green_ip $ping_pid_file | grep -F '% packet loss' > $ping_summary_file &
ping_pid=$!

kill_red
await_red
launch_red
await_red_l3tc_up

sleep 2

kill_green
await_green
launch_green
await_green_l3tc_up

sleep 2

e red pkill -INT -F $ping_pid_file

wait $ping_pid

loss_summary=$(cat $ping_summary_file)

loss_pct=$(echo $loss_summary | grep -o '[0-9]\+% packet loss' | grep -o '[0-9]\+')

echo "Summary: '${loss_summary}'"

if [ $loss_pct -gt 1 ]; then
    echo "More than 1% percent of packets were lost."
    exit 1
fi

