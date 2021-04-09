import numpy as np
import csv
import utm
from scipy import stats
from statsmodels import robust
import sys
 
import datetime
import time

out = str(sys.argv[3]) 

def timestamp(date):
    return time.mktime(date.timetuple())

def dataAnalysis(name, X, Y, T):
	points = len(X)
	subT = []
	subDist = []
	subV = []
	for k in range(points-1):
		subT.append(abs(T[k+1]-T[k]))
		subDist.append( (X[k+1]-X[k])**2 + (Y[k+1]-Y[k])**2 )
		if subT[k] != 0:
			subV.append(np.sqrt(subDist[k])/subT[k])
		else:
			subV.append(0)

	try:
		tmin = min(subT)
		tavg = np.mean(subT)
		tmax = max(subT)
		tstd = np.std(subT)
		tmode = stats.mode(subT)
		tQ1 = np.quantile(subT, 0.1)
		tQ25 = np.quantile(subT, 0.25)
		tQ75 = np.quantile(subT, 0.75)
		tQ9 = np.quantile(subT, 0.9)
		tskew = stats.skew(subT)
		tMAD = robust.mad(subT)
	except:
		print('Empty array of subT')

	try:
		dmin = min(subDist)
		davg = np.mean(subDist)
		dmax = max(subDist)
		dstd = np.std(subDist)
		dmode = stats.mode(subDist)
		dQ1 = np.quantile(subDist, 0.1)
		dQ25 = np.quantile(subDist, 0.25)
		dQ75 = np.quantile(subDist, 0.75)
		dQ9 = np.quantile(subDist, 0.9)
		dskew = stats.skew(subDist)
		dMAD = robust.mad(subDist)
	except:
		print('Empty array of subDist')

	try:
		Vmin = min(subV)
		Vavg = np.mean(subV)
		Vmax = max(subV)
		Vstd = np.std(subV)
		Vmode = stats.mode(subV)
		VQ1 = np.quantile(subV, 0.1)
		VQ25 = np.quantile(subV, 0.25)
		VQ75 = np.quantile(subV, 0.75)
		VQ9 = np.quantile(subV, 0.9)
		Vskew = stats.skew(subV)
		VMAD = robust.mad(subV)
	except:
		print('Empty array of subV')

	try:
		with open(str(sys.argv[2]), 'a+') as the_file:
			message = name+ ','+str(points)+','
			message += str(tmin) + ',' + str(tmax) + ',' + str(tavg) + ',' + str(tstd) + ',' + str(tmode[0]) +','+ str(tmode[1]) + ',' + str(tQ1)  + ',' + str(tQ25) + ',' + str(tQ75) + ',' + str(tQ9)  + ',' + str(tskew) + ',' + str(tMAD) + ','
			message += str(dmin) + ',' + str(dmax) + ',' + str(davg) + ',' + str(dstd) + ',' + str(dmode[0]) +','+ str(dmode[1]) + ',' + str(dQ1)  + ',' + str(dQ25) + ',' + str(dQ75) + ',' + str(dQ9)  + ','+ str((dQ75-dQ25)/(dQ75+dQ25))+','+ str(dskew) + ',' + str(dMAD) + ','
			message += str(Vmin) + ',' + str(Vmax) + ',' + str(Vavg) + ',' + str(Vstd) + ',' + str(Vmode[0]) +','+ str(Vmode[1]) + ',' + str(VQ1)  + ',' + str(VQ25) + ',' + str(VQ75) + ',' + str(VQ9)  + ','+ str((VQ75-VQ25)/(VQ75+VQ25))+','+ str(Vskew) + ',' + str(VMAD) + '\n'
			the_file.write(message)
	except:
		print('Nothing to write')
	return

titleVec = []
the_titles = open('title.csv')
line = the_titles.readline()
while line:
	titleVec.append(int(line))
	line = the_titles.readline()
the_titles.close()


with open(str(sys.argv[1])) as f:
	print('opened')
	data = csv.DictReader(f)
	count = 0
	utmdata = ''
	name = str(sys.argv[1])[9:]
	X = []
	Y = []
	T = []
	quad = ''
	flag = 0
	error_list = []

	for row in data:
		utm_dic = utm.from_latlon(float(row['Latitude']), float(row['Longitude']))
		X.append(utm_dic[0])
		Y.append(utm_dic[1])
		stamp = datetime.datetime.strptime(str(row['Date'])+'/'+str(row['Time']), '%Y/%m/%d/%H:%M:%S')

		utmdata += str(utm_dic[0]) + ',' + str(utm_dic[1]) + ',' + str(int(timestamp(stamp))) + '\n'
		T.append(timestamp(stamp))
		if (quad !='')&(quad != str(utm_dic[2])):
			flag = 1
		quad = str(utm_dic[2])

	if len(X)<2000:
		dataAnalysis(name, X, Y, T)
	file = open(out+'/'+name,'a+')
	file.write(utmdata[:-1])
