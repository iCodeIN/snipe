#!/usr/bin/env -S bash -eu
pip3 install snmpsim --user
$(readlink -f ~/.local/bin/snmpsimd.py) --data-dir="$(readlink -f ~/.local/snmpsim/data)" --agent-udpv4-endpoint=0.0.0.0:1024
# snmpwalk -v 3 -l authPriv -n mib2dev/ip-mib -x DES -X privatus -a MD5 -A auctoritas -u simulator 127.0.0.1:1024 1
