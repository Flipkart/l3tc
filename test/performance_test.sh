#!/bin/bash

port=9876
export TCP_PORTS=$port

function bad_usage {
    echo "USAGE: ./performance_test.sh <payload_file> <compression_level> <additional opts>"
    echo "Error message: $1"
    exit 1
}

if [ "x$1" == "x" ]; then
    bad_usage "Payload-file missing. Payload-file is data file which will be pulled over compressed-pipe. Packet-capture of real-workload is ideal payload for performance-testing purpose."
fi
payload_file=$1

if [ ! -f $payload_file ]; then
    bad_usage "Payload-file $payload_file does NOT FOUND."
fi

if [ "x$2" == "x" ]; then
    bad_usage "Please provide compression-level. The script does not default to a value to ensure performance-test parameters are controlled correctly."
fi
compression_level=$2

echo $compression_level | grep -q '^[0-9]\+$'
if [ $? -ne 0 ]; then
    bad_usage "Compression-level '${compression_level}' must be an integer"
fi

additional_opts="$3 "
echo "Using additional opts: $additional_opts"

log_severity_frag=" " #so that it doesn't default to too verbose severity level

. _single_l2_domain_setup.sh

cat $payload_file | e green nc -l -p $port --send-only &
server_pid=$!

sleep 1

#warm-up
e red nc $green_ip $port >/dev/null
wait $server_pid

#real run
cat $payload_file | e green nc -l -p $port --send-only &
server_pid=$!

sleep 1

f_green_tx_before=$tmp_dir/green_tx_bytes.before
f_green_tx_after=$tmp_dir/green_tx_bytes.after
f_red_rx_before=$tmp_dir/red_rx_bytes.before
f_red_rx_after=$tmp_dir/red_rx_bytes.after
f_bytes_xfered=$tmp_dir/bytes.received

f_green_ucpu_before=$tmp_dir/green_ucpu.before
f_green_ucpu_after=$tmp_dir/green_ucpu.after
f_red_ucpu_before=$tmp_dir/red_ucpu.before
f_red_ucpu_after=$tmp_dir/red_ucpu.after

f_green_scpu_before=$tmp_dir/green_scpu.before
f_green_scpu_after=$tmp_dir/green_scpu.after
f_red_scpu_before=$tmp_dir/red_scpu.before
f_red_scpu_after=$tmp_dir/red_scpu.after

e sw ifconfig g0 | grep 'TX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_green_tx_before
e sw ifconfig r0 | grep 'RX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_red_rx_before

red_l3tc_pid=$(cat $red_pid_file)
green_l3tc_pid=$(cat $green_pid_file)

red_ucpu_before=$(cat /proc/$red_l3tc_pid/stat | cut -d' ' -f14)
green_ucpu_before=$(cat /proc/$green_l3tc_pid/stat | cut -d' ' -f14)
red_scpu_before=$(cat /proc/$red_l3tc_pid/stat | cut -d' ' -f15)
green_scpu_before=$(cat /proc/$green_l3tc_pid/stat | cut -d' ' -f15)

start_time_ns=$(date +%s%N)
e red nc $green_ip $port | wc -c > $f_bytes_xfered
end_time_ns=$(date +%s%N)

red_ucpu_after=$(cat /proc/$red_l3tc_pid/stat | cut -d' ' -f14)
green_ucpu_after=$(cat /proc/$green_l3tc_pid/stat | cut -d' ' -f14)
red_scpu_after=$(cat /proc/$red_l3tc_pid/stat | cut -d' ' -f15)
green_scpu_after=$(cat /proc/$green_l3tc_pid/stat | cut -d' ' -f15)

wait $server_pid

e sw ifconfig g0 | grep 'TX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_green_tx_after
e sw ifconfig r0 | grep 'RX' | grep -o 'bytes [0-9]\+' | cut -d' ' -f2 > $f_red_rx_after

bytes_xfered=$(cat $f_bytes_xfered)
file_sz=$(cat $payload_file | wc -c)

if [ $file_sz -ne $bytes_xfered ]; then
    echo "Incomplete transfer: Original file has $fize_sz bytes, whereas only $bytes_xfered bytes were copied-over."
    exit 1
fi

set +e
green_tx=$(expr $(cat $f_green_tx_after) '-' $(cat $f_green_tx_before))
red_rx=$(expr $(cat $f_red_rx_after) '-' $(cat $f_red_rx_before))
compression_ratio=$(expr $bytes_xfered '/' $red_rx)
compressor_side_ucpu=$(expr $green_ucpu_after '-' $green_ucpu_before)
decompressor_side_ucpu=$(expr $red_ucpu_after '-' $red_ucpu_before)
compressor_side_scpu=$(expr $green_scpu_after '-' $green_scpu_before)
decompressor_side_scpu=$(expr $red_scpu_after '-' $red_scpu_before)
elapsed_time=$(expr '(' $end_time_ns '-' $start_time_ns ')' '/' 1000)

cat <<EOF | tee -a $tmp_dir/performance.report
=========================================[ REPORT ]=========================================
Configuration: 
    Compression level:    $compression_level
    Additional opts:      '$additional_opts'
    Payload file:         $payload_file (sz: $file_sz)
----

Compression ratio:        $compression_ratio
Compressing side CPU:
    User:                 $compressor_side_ucpu
    System:               $compressor_side_scpu
De-compressing side CPU:
    User:                 $decompressor_side_ucpu
    System:               $decompressor_side_scpu
Elapsed time:             $elapsed_time us
============================================================================================
EOF
set -e

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

