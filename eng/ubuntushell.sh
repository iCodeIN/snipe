#!/bin/bash -eu

apt update
apt install -y iproute2 snmp
export SNMP_SERVER=$(hostname -I | awk -F '\t' '{ sub(/[^\\.]*$/, "", $NF) } 1')1
snmpwalk -v 3 -l authPriv -n mib2dev/ip-mib -x DES -X privatus -a MD5 -A auctoritas -u simulator ${SNMP_SERVER}:1024 1
ip a
bash