#!/bin/bash

# set up ip table for the pi
cd --
echo 1 > /proc/sys/net/ipv4/ip_forward
/sbin/iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE
/sbin/iptables -A FORWARD -i ens3 -o ens4 -m state --state RELATED,ESTABLISHED
/sbin/iptables -A FORWARD -i ens4 -o ens3 -j ACCEPT

echo "----------------------PIMAN MONITOIRNG START---------------------"
# run the pi client keep asking monitoring data from each of the Pi


# checks for monitroing file path
# if not set, exits
if [[ -z "/usr/local/fresno/monitoring/logs/monitor.log" ]]; then
    echo "ERROR: MONITORING_LOG_PATH not set globally. Please reference the README.md and set the environ. var"
    echo "exiting..."
    exit 1
fi

cd /usr/local/fresno/monitoring
python3 monitoring-client.py monitoring.config /usr/local/fresno/monitoring/logs/monitor.log /home/cs158b/fresno/hosts.csv
