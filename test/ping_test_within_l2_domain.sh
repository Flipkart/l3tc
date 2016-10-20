#!/bin/bash

. _single_l2_domain_setup.sh

e red ping -A -c 1000 $green_ip
e red ping -A -c 1000 $blue_ip
e green ping -A -c 1000 $blue_ip
e green ping -A -c 1000 $red_ip
e blue ping -A -c 1000 $red_ip
e blue ping -A -c 1000 $green_ip

