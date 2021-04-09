#!/bin/bash
count=1
touch timings.csv
echo "Challenge, tgen, tsplit, tsig, tver, out">timings.csv
for i in `seq 1 10950`;
do 
	./MPCmult
	echo $count;
	((count++)) 
done 
