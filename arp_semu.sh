#!/bin/bash

level=${1-5}
wifidog -a ./arp_semu.txt -c wifidog-1.3.0/wifidog.pc.conf -d $level -f
