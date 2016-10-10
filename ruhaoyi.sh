#!/bin/bash
cd wifidog-1.3.0
./autogen.sh >>/dev/null
make >>/dev/null
make install >>/dev/null
mkdir -p /usr/local/etc
cp -n wifidog-msg.html /usr/local/etc/
cd ->>/dev/null
