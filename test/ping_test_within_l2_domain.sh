#!/bin/bash

. _single_l2_domain_setup.sh

e red ping -c 1 $green_ip
e red ping -c 1 $blue_ip
e green ping -c 1 $blue_ip
e green ping -c 1 $red_ip
e blue ping -c 1 $red_ip
e blue ping -c 1 $green_ip

