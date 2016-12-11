#!/bin/bash
if [ ! $1 ]; then
  OPENWRT_BASE_DIR="../trunk-openwrt2/openwrt"
else
  OPENWRT_BASE_DIR="$1"
fi  
echo "OPENWRT_BASE_DIR=$OPENWRT_BASE_DIR"
./compress.sh
mv -f wifidog-1.3.0-1.3.0.tar.gz $OPENWRT_BASE_DIR/dl/
rm -rf $OPENWRT_BASE_DIR/build_dir/target-mipsel_24kec+dsp_musl-1.1.14/wifidog-normal/
cd $OPENWRT_BASE_DIR > /dev/null
make V=99
cd -> /dev/null


