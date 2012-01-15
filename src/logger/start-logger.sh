#!/bin/bash

# change to directory of script
cd "`dirname "$0"`"
# load config variables
source ./logging-config

# start daemonlogger
for interface in "eth0" "eth1" "eth2"
do
    sudo /usr/bin/daemonlogger -l /home/logger/logs -i $interface -n $interface.pcap -t $ROLLOVER_TIME -u logger -d
done
