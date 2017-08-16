#!/bin/bash

min=60
lines=`cat $1 | wc -l`

if [ "$lines" -ge "$min" ]
then
	 grep Total $1 | tail -n $min | awk '{ sum += $NF } END { print "msgs/s:", sum / NR }'
	 grep -v "HH:MM:SS" $2 | grep -v "Time" | tail -n $min | awk '{ rx += $2; tx += $3 } END { print "rx:", (rx * 8) / (NR*1024*1024); print "tx:", (tx * 8) / (NR*1024*1024); print "all:", ((rx+tx) * 8) / (NR*1024*1024) }'
else
	 printf "Not enough lines. Found: %d, minimum: %d\n" $lines $min 
fi
