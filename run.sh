#!/bin/bash
trap 'echo test; exit 0' 11 13

level=${1-6}
wifidog -c wifidog-1.3.0/wifidog.pc.conf -d $level -s -f
