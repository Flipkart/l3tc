#!/bin/bash

set -x
set -e

tc_tcp_ports=${TCP_PORTS:-80,443}
tc_icmp=${ICMP:-y}
tc_nf_mark_value=${MARK_VALUE:-1}
tc_routing_tbl=${ROUTING_TABLE:-1}
tc_ipset_name=${IPSET_NAME:-l3tc}

set +e
ipset list | grep -qF "Name: $tc_ipset_name"
ipset_exists=$?
set -e
if [ $ipset_exists -eq 0 ]; then
    ipset destroy $tc_ipset_name
fi
ipset create $tc_ipset_name hash:ip
tcp_pkt_mark="OUTPUT -t mangle -p tcp -m set --match-set ${tc_ipset_name} dst -m multiport --ports ${tc_tcp_ports} -j MARK --set-mark ${tc_nf_mark_value}"
icmp_pkt_mark="OUTPUT -t mangle -p icmp -m set --match-set ${tc_ipset_name} dst -j MARK --set-mark ${tc_nf_mark_value}"
set +e
echo $tcp_pkt_mark | xargs iptables -C
has_tcp_mark=$?
echo $icmp_pkt_mark | xargs iptables -C
has_icmp_mark=$?
set -e

if [ $has_tcp_mark -ne 0 ]; then
    echo $tcp_pkt_mark | xargs iptables -A
fi

if [ $has_icmp_mark -ne 0 ]; then
    if [ "x$tc_icmp" == "xy" ]; then
        echo $icmp_pkt_mark | xargs iptables -A
    fi
else
    if [ "x$tc_icmp" != "xy" ]; then
        echo $icmp_pkt_mark | xargs iptables -D
    fi
fi

ip link set $TUN_IFACE up

ip route add 0.0.0.0/0 dev $TUN_IFACE table $tc_routing_tbl

ip rule add from all fwmark $tc_nf_mark_value table $tc_routing_tbl
