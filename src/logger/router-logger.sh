#!/bin/sh

sudo /usr/bin/daemonlogger -l /home/logger/logs -i eth0 -n eth0.pcap -t 5m -u logger -d
sudo /usr/bin/daemonlogger -l /home/logger/logs -i eth1 -n eth1.pcap -t 5m -u logger -d
sudo /usr/bin/daemonlogger -l /home/logger/logs -i eth2 -n eth2.pcap -t 5m -u logger -d
