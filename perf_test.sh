#!/bin/bash
TEMPFILE=./tmp$RANDOM.sh
trap "trapAction $TEMPFILE; exit 0" 2 10

MODE=${1-sdl}
WAN_IF=${2-eth0}
PLACE_CODE=${3-`ifconfig $WAN_IF|grep ether|awk '{print $2}'|tr -d ":"|tr '[a-z]' '[A-Z]'`}

trapAction()
{
  echo ----------signal captured!----------
  rm -rf $1;
  ps -ef|grep -E $0|grep -v "grep"|awk '{ print $2}'|xargs kill -9;
}


showUsage()
{
  echo "Usage: $1 {single|round|sdl|mdl} {WAN_IF} {PLACE_CODE}"
  echo ""
  echo "      single:  execute the script of adding maximum users in a single way"
  echo "      round :  execute the script of adding and deleting maximum users in roundtrip"
  echo "      sdl   :  execute the script of adding and deleting maximum users in deadloop by single-thread"
  echo "      mdl   :  execute the script of adding and deleting maximum users in deadloop by multi-thread"
}

makeScript()
{
    DEVICE_IP=`ifconfig -a|grep inet|grep -v 127.0.0.1|grep -v inet6|awk '{print $2}'|tr -d "addr:"`
    head -130 arp_semu.txt|sed '1d'|tr -d ':'|awk '{printf("curl \047http://router.ruhaoyi.com:9977/Server/r/pass?user_mac=%s&user_ip=%s&phone_tel=1380000%04d&record_id=1%05d&device_ip=88.88.88.88&is_release=1&identify_code=6%03d&place_code=1001\047\n",$4,$1,NR,NR,NR)}'|tee $TEMPFILE >> /dev/null
#    sed '1i\#!/bin/bash' $1 >>/dev/null
    sed -i 's/device_ip=88.88.88.88/device_ip='$DEVICE_IP'/g' $1 >>/dev/null
    [ $2 == 1 ] && head -130 arp_semu.txt|sed '1d'|awk '{printf("wdctl logout %s\n", $1)}'|tee >> $TEMPFILE
    chmod 777 $1
}

makeScript2()
{
#    PLACE_CODE=`ifconfig -a|grep ether|awk '{print $2}'|tr -d ":"|tr '[a-z]' '[A-Z]'`
    head -130 arp_semu.txt|sed '1d'|tr -d ':'|awk '{printf("curl \047http://router.ruhaoyi.com:9977/Server/r/pass?user_mac=%s&user_ip=%s&phone_tel=1380000%04d&record_id=1%05d&is_release=1&identify_code=6%03d&place_code=888888888888\047\n",$4,$1,NR,NR,NR)}'|tee $2 >> /dev/null
    sed -i 's/place_code=888888888888/place_code='$PLACE_CODE'/g' $2 >>/dev/null
    [ $3 == 1 ] && head -130 arp_semu.txt|sed '1d'|awk '{printf("wdctl logout %s\n", $1)}'|tee >> $2
    chmod 777 $2
}

execScript()
{
  . $TEMPFILE
}

case "$1" in
  single|round|sdl|mdl)
    ;;
  *)
#    echo $MODE
#    echo $WAN_IF
#    echo $PLACE_CODE
    showUsage $0
    exit 1
esac

case "$MODE" in
  single)
    makeScript2 $PLACE_CODE "$TEMPFILE" 0 
    execScript
    ;;
  round)
    makeScript2 $PLACE_CODE "$TEMPFILE" 1
    chmod 777 $TEMPFILE
    execScript
    ;;
  
  sdl)
    makeScript2 $PLACE_CODE "$TEMPFILE" 1
    while :
    do
      execScript
    done   
    ;;
  mdl)
    makeScript2 $PLACE_CODE "$TEMPFILE" 1
    for ((m=0; m<10; m++))
    do
      for ((n=0; n<2; n++))
      do
      {
        execScript
      }&
      done  
      wait
    done
    ;;
esac
echo ""
rm -f $TEMPFILE

