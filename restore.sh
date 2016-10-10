#!/bin/bash
cd wifidog-1.3.0>>/dev/null
if [ -f "Makefile" ]; then
  make uninstall>>/dev/null 2>&1
  make distclean>>/dev/null
  rm -f Makefile
fi
find ./ -name "Makefile*"|grep -v "contrib"|grep -v ".am"|xargs rm -f
find ./ -name "*deps"|xargs rm -f
find ./ -name "config*"|grep -v "configure.ac"|xargs rm -rf
rm -rf autom4te.cache doc/html >>/dev/null 2>&1
rm -f aclocal.m4 libtool src/wdctl src/wifidog stamp-h1 wifidog-msg.html wifidog.spec>>/dev/null 2>&1
cd ->>/dev/null
