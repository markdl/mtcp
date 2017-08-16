#!/bin/bash

min=60
lines=`grep ALL $1 | wc -l`

if [ "$lines" -ge "$min" ]
then
	 grep Total $1 | tail -n $min | awk '{ sum += $NF } END { print "msgs/s:", sum / NR }'
	 grep ALL $1 | tail -n $min | awk '{ rx += $11; tx += $14 } END { print "rx:", rx / NR; print "tx:", tx / NR; print "all:", (rx+tx) / NR }'
else
	 printf "Not enough lines. Found: %d, minimum: %d\n" $lines $min 
fi
