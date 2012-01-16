#!/bin/bash

# change to directory of script
cd "`dirname "$0"`"
# load config variables
source ./logging-config

cd $LOGDIR
find . -type f -mmin +1 -print | rsync -auvz -e "ssh -i $HOME/.ssh/id_rsa" --files-from=- . "$LOG_SERVER":~/logs/
