#!/bin/bash
mkdir bin
for i in datatest/*; # Needs to be datatest/
do 
	echo $i 
	gpsbabel -t -i unicsv -f $i -x track,speed -o unicsv -F $i 	# Extract speed information from unicsv
	python2 rmvOddPoints.py $i 10 								# Remove points with instant speed above 10m/s
	gpsbabel -t -i unicsv -f $i -x interpolate,time=3 -o unicsv -F $i 			# Interpolate time
	gpsbabel -t -i unicsv -f $i -x interpolate,distance=0.30 -o unicsv -F $i 	# Interpolate distance
	python3 interpolatedToUtm.py $i bin.csv bin									# Convert to UTM and save
done