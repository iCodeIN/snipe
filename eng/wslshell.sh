#!/bin/bash -eu

sudo /usr/sbin/sshd
SRCDIR=$(dirname "${BASH_SOURCE}")
${SRCDIR}/simulator.sh &
trap "trap - SIGTERM && sudo kill -- -$$" SIGINT SIGTERM EXIT
sudo podman run -v $(readlink -f ${SRCDIR})/:/eng/ -it ubuntu /eng/ubuntushell.sh
