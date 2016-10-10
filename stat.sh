#!/bin/bash
FILE=./data.txt
while true
do
  uptime>>$FILE
  wdctl status>>$FILE
  wdctl statistics>>$FILE
  vmstat>>$FILE
  mpstat -P ALL>>$FILE
  pidstat>>$FILE
  iostat -xz>>$FILE
  free -m>>$FILE
  sar -n DEV >>$FILE
  sar -n TCP,UDP,SOCK 1 1 
  sleep 30
  echo ----------------------------------
done
