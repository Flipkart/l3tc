#!/bin/bash

function print_rxtx() {
    sudo ifconfig eth0 | grep -F 'RX bytes' | sed -e 's/:/ /g' | awk '{print $3 " " $(NF - 2)}'
}

rxtx=$(print_rxtx)
rx_before=$(echo $rxtx | cut -d' ' -f1)
tx_before=$(echo $rxtx | cut -d' ' -f2)

$*

rxtx=$(print_rxtx)
rx_after=$(echo $rxtx | cut -d' ' -f1)
tx_after=$(echo $rxtx | cut -d' ' -f2)

eff_rx=$(expr $rx_after - $rx_before)
eff_tx=$(expr $tx_after - $tx_before)
echo -e "\e[1;33m B:\t\tRx: ${eff_rx}\t\t Tx: ${eff_tx} \e[0;m"

eff_rx_kb=$(expr $eff_rx / 1024)
eff_tx_kb=$(expr $eff_tx / 1024)
echo -e "\e[1;34m KB:\t\tRx: ${eff_rx_kb}\t\t Tx: ${eff_tx_kb} \e[0;m"

eff_rx_mb=$(expr $eff_rx_kb / 1024)
eff_tx_mb=$(expr $eff_tx_kb / 1024)
echo -e "\e[1;35m MB:\t\tRx: ${eff_rx_mb}\t\t Tx: ${eff_tx_mb} \e[0;m"
