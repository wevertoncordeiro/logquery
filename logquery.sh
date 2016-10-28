#!/bin/bash
#
# logquery 	Start the Log Analyzer logquery server.
#

# The variables below are NOT to be changed.  They are there to make the
# script more readable.

# Daemon name
NAME=logquery

# Directory in which we are running the process
WORK_DIR=`pwd`

# Full daemon path
DAEMON=$WORK_DIR/src/$NAME

### Config variables ##############################################

# Directory in which Netfilter logs are stored.
FIREWALL=$WORK_DIR/log/netfilter/

# Directory in which DNS logs are stored.
DNS=$WORK_DIR/log/bind/

# User that will be used to run the daemon
# USER=logquery

# Address that will be used for listening
ADDRESS=0.0.0.0

# Port that will be used for listening
PORT=65000

# File in which NAT table can be found
NAT=$WORK_DIR/xml/nat.xml

# File in which config options can be found
CONFIG=$WORK_DIR/xml/conf.xml

# Run in background
BACKGROUND=true

### Main process ##################################################

OPT_START="-a $ADDRESS -p $PORT -f $FIREWALL -d $DNS -n $NAT -c $CONFIG"

case $BACKGROUND in
	true)
		OPT_START="$OPT_START -k start"
	;;
	false)
		true;
	;;
	*)
		echo "Invalid value for BACKGROUND"
		exit 1
	;;
esac

should_start() {
    if [ -e $DAEMON ]; then
    	if [ ! -x $DAEMON ]; then
		echo "$NAME is not executable, not starting"
		exit 0
	fi
    else
	echo "$NAME not found"
	exit 0
    fi
}

case "$1" in
  start)
    should_start
    echo -n "Starting $NAME server:"
    if $DAEMON $OPT_START; then
      echo " $NAME."
      exit 0
    else
      echo " failed"
      exit 1
    fi
    ;;

  stop)
    should_start
    echo -n "Stopping $NAME server:"
    if $DAEMON -k stop; then
      echo " $NAME."
      exit 0
    else
      echo " failed"
      exit 1
    fi
    ;;

  restart)
    $0 stop
    $0 start
    ;;

  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac

