#!/bin/bash
count=1
touch TimeProve.csv
touch TimeVer.csv
echo "input, total, tgen, tsplit, tsign">TimeProve.csv
echo "tver">TimeVer.csv
for i in `seq 1 100`;
do
	./a.out <<<$(( ( RANDOM % 1234567890 )  + 1 ))
	./boolVerif
done

