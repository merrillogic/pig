#!/bin/bash

for i in {129..255}
do
    ping 137.22.73.$i -c 1
    arp -a 137.22.73.$i >> ~/arp-tables
done

