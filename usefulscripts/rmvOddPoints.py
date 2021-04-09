import csv
import sys

with open(str(sys.argv[1])) as fin:
	reader = csv.DictReader(fin)

	output = 'No,Latitude,Longitude,Speed,Date,Time\n'
	# iterate and write rows based on condition
	for row in reader:
		if (row['Speed'] != ''):
			if float(row['Speed']) < int(sys.argv[2]):
				output += row['No'] + ',' + row['Latitude'] + ',' + row['Longitude'] + ',' + row['Speed'] + ',' + row['Date'] + ',' + row['Time'] + '\n'

	file = open(str(sys.argv[1]),'w')
	file.write(output)