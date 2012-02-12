#!/bin/bash

# change to directory of script
cd "`dirname "$0"`"
# load config variables
source ./logging-config

# start daemonlogger
for interface in "br0" "eth1" "eth2"
do
    sudo /usr/bin/daemonlogger -l $LOGDIR -i $interface -n $interface.pcap -s $ROLLOVER_SIZE -t $ROLLOVER_TIME -u logger -d
done
