#!/bin/bash

# change to directory of script
cd "`dirname "$0"`"
# load config variables
source ./logging-config

cd $LOGDIR
find . -type f -mmin +1 -print | xargs -n 1 $HOME/honeynet/src/honeynet_web/manage.py parse_pcap --settings=honeynet_web.settings_production
