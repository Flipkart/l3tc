#!/bin/bash

port=9876
export TCP_PORTS=$port

. _single_l2_domain_setup.sh

bytes=$(expr 1024 '*' 1024 '*' 10)

head -c $bytes /dev/zero | e green nc -l -p $port --send-only &
server_pid=$!

sleep 1

f_green_tx_before=$tmp_dir/green_tx_bytes.before
f_green_tx_after=$tmp_dir/green_tx_bytes.after
f_red_rx_before=$tmp_dir/red_rx_bytes.before
f_red_rx_after=$tmp_dir/red_rx_bytes.after
f_bytes_xfered=$tmp_dir/bytes.received

e sw ifconfig g0 | grep 'TX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_green_tx_before
e sw ifconfig r0 | grep 'RX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_red_rx_before

e red nc $green_ip $port | wc -c > $f_bytes_xfered

wait $server_pid

e sw ifconfig g0 | grep 'TX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_green_tx_after
e sw ifconfig r0 | grep 'RX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_red_rx_after

bytes_xfered=$(cat $f_bytes_xfered)

if [ $bytes -ne $bytes_xfered ]; then
    echo "Incomplete transfer: Source was supposed to push $bytes bytes, whereas only $bytes_xfered bytes were copied-over."
    exit 1
fi

green_tx=$(expr $(cat $f_green_tx_after) '-' $(cat $f_green_tx_before))
red_rx=$(expr $(cat $f_red_rx_after) '-' $(cat $f_red_rx_before))
compression_ratio=$(expr $bytes_xfered '/' $red_rx)
echo "Compression ratio: $compression_ratio"

if [ $compression_ratio -lt 100 ]; then
    echo "compression ratio ($compression_ratio) was less than 100"
    exit 1
fi

one_pct=$(expr $red_rx '/' 100)

if [ $green_tx -ne $red_rx ]; then
    rx_tx_diff=$(expr $green_tx '-' $red_rx)
    if [ $rx_tx_diff -lt 0 ]; then
        rx_tx_diff=$(expr '-1' '*' $rx_tx_diff)
    fi
    if [ $rx_tx_diff -gt $one_pct ]; then
        echo "TX ($green_tx) and RX ($red_rx) didn't match, difference was: $rx_tx_diff (which is greater than 1%: $one_pct)"
    fi
    exit 1
fi

