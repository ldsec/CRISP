import numpy as np # linear algebra
import csv
from datetime import datetime
import utm

out = 'data' 

## Extract the different routes in GPS coordinates into data$i/

titleVec = []
the_titles = open('title.csv')
line = the_titles.readline()
while line:
	titleVec.append(int(line))
	line = the_titles.readline()
the_titles.close()

with open('subtraces.csv') as f:
	print('opened')
	data = csv.DictReader(f)
	count = 0
	gpsdata = 'lat,lon,date,time'+'\n'
	name = '0'
	lat = []
	lon = []
	T = []
	quad = ''
	flag = 0
	error_list = []


	for row in data:
		if (int(row['activityID']) in titleVec[max(0,count-100):count+100])&(int(row['activityID']) == count):
			timestamp = int(row['timeBegin'])
			dt_object = datetime.fromtimestamp(timestamp)
			date = dt_object.date().strftime('%Y/%m/%d')
			time = dt_object.time()
			gpsdata += row['lat'] + ',' + row['long'] + ',' + str(date) + ',' + str(time) + '\n'
			lat.append(float(row['lat']))
			lon.append(float(row['long']))
			T.append(int(row['timeBegin']))

		elif(int(row['activityID']) in titleVec):
			if (name!=str(0))&(T != [])&(lat != []):
				if flag==1:
					error_list.append(int(row['activityID']))
					print('error quadran - %2d'%int(row['activityID']))
					errorFile = open('error.csv', 'a')
					errorFile.write(row['activityID']+'\n')
				else:
					file = open(out+str(row['typeID'])+'/'+name+'.txt','w')
					file.write(gpsdata[:-1])
			name = row['activityID'] + '-' + datetime.fromtimestamp(int(row['timeBegin'])).strftime('%Y%m%d%H%M%S')
			count += 1
			gpsdata = 'lat,lon,date,time'+'\n'
			lat = []
			lon = []
			T = []
			quad = ''
			flag = 0
			print(count)
		else:
			count += 1 
			print(count)

print(error_list)