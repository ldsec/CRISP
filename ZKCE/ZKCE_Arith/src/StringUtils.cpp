/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "StringUtils.h"
#include <sstream>

//----------------------------------------------------------------------------------
//   SHOW ARRAY
//----------------------------------------------------------------------------------


void StringUtils::showVec(long* vals, long size) {
	cout << "[";
	for (long i = 0; i < size; ++i) {
		cout << vals[i] << ", ";
	}
	cout << "]" << endl;
}

void StringUtils::showVec(double* vals, long size) {
	cout << "[";
	for (long i = 0; i < size; ++i) {
		cout << vals[i] << ", ";
	}
	cout << "]" << endl;
}

void StringUtils::showVec(complex<double>* vals, long size) {
	cout << "[";
	for (long i = 0; i < size; ++i) {
		cout << vals[i] << ", ";
	}
	cout << "]" << endl;
}

void StringUtils::showVec(ZZ* vals, long size) {
	cout << "[";
	for (long i = 0; i < size; ++i) {
		cout << vals[i] << ", ";
	}
	cout << "]" << endl;
}

string StringUtils::toString(ZZ* vals, long size) {

	std::ostringstream strs;

	for (long i = 0; i < size; ++i) {
    	strs << vals[i];
	}
	std::string str_res = strs.str();
    return str_res;
}


string StringUtils::toString(complex<double>* vals, long size) {

	std::ostringstream strs;

	for (long i = 0; i < size; ++i) {
    	strs << vals[i];
	}
	std::string str_res = strs.str();
    return str_res;
}


//----------------------------------------------------------------------------------
//   SHOW & COMPARE ARRAY
//----------------------------------------------------------------------------------


void StringUtils::compare(double val1, double val2, string prefix) {
	cout << "---------------------" << endl;
	cout << "m" + prefix + ":" << val1 << endl;
	cout << "d" + prefix + ":" << val2 << endl;
	cout << "e" + prefix + ":" << val1-val2 << endl;
	cout << "---------------------" << endl;
}

void StringUtils::compare(complex<double> val1, complex<double> val2, string prefix) {
	cout << "---------------------" << endl;
	cout << "m" + prefix + ":" << val1 << endl;
	cout << "d" + prefix + ":" << val2 << endl;
	cout << "e" + prefix + ":" << val1-val2 << endl;
	cout << "---------------------" << endl;
}

void StringUtils::compare(double* vals1, double* vals2, long size, string prefix) {
	for (long i = 0; i < size; ++i) {
		cout << "---------------------" << endl;
		cout << "m" + prefix + ": " << i << " :" << vals1[i] << endl;
		cout << "d" + prefix + ": " << i << " :" << vals2[i] << endl;
		cout << "e" + prefix + ": " << i << " :" << (vals1[i]-vals2[i]) << endl;
		cout << "---------------------" << endl;
	}	
}

void StringUtils::compare(complex<double>* vals1, complex<double>* vals2, long size, string prefix) {
	
	complex<double> mean2;
	complex<double> mean;
	complex<double> dist;
	for (long i = 0; i < size; ++i) {
		// Uncomment to get detail for each slot
		/*cout << "---------------------" << endl;
		cout << "m" + prefix + ": " << i << " :" << vals1[i] << endl;
		cout << "d" + prefix + ": " << i << " :" << vals2[i] << endl;
		cout << "e" + prefix + ": " << i << " :" << (vals1[i]-vals2[i]) << endl;
		cout << "---------------------" << endl;*/
		
		dist = dist + vals1[i].real();
		complex<double> m = (vals1[i]-vals2[i]);
		mean2 = mean2 + complex<double>(pow(m.real(), 2), 0);
		mean = mean + complex<double>(m.real(), 0);
	}
	cout << "Total:" << dist << endl;
	cout << "RMSE :" << complex<double>(sqrt(mean2.real()/size), sqrt(mean2.imag()/size)) << endl;
	cout << "Total Error :" << complex<double>(mean.real(), mean.imag()) << endl;
}


void StringUtils::compare(double* vals1, double val2, long size, string prefix) {
	for (long i = 0; i < size; ++i) {
		cout << "---------------------" << endl;
		cout << "m" + prefix + ": " << i << " :" << vals1[i] << endl;
		cout << "d" + prefix + ": " << i << " :" << val2 << endl;
		cout << "e" + prefix + ": " << i << " :" << vals1[i]-val2 << endl;
		cout << "---------------------" << endl;
	}
}

void StringUtils::compare(complex<double>* vals1, complex<double> val2, long size, string prefix) {
	for (long i = 0; i < size; ++i) {
		cout << "---------------------" << endl;
		cout << "m" + prefix + ": " << i << " :" << vals1[i] << endl;
		cout << "d" + prefix + ": " << i << " :" << val2 << endl;
		cout << "e" + prefix + ": " << i << " :" << vals1[i]-val2 << endl;
		cout << "---------------------" << endl;
	}
}

void StringUtils::compare(double val1, double* vals2, long size, string prefix) {
	for (long i = 0; i < size; ++i) {
		cout << "---------------------" << endl;
		cout << "m" + prefix + ": " << i << " :" << val1 << endl;
		cout << "d" + prefix + ": " << i << " :" << vals2[i] << endl;
		cout << "e" + prefix + ": " << i << " :" << val1-vals2[i] << endl;
		cout << "---------------------" << endl;
	}
}

void StringUtils::compare(complex<double> val1, complex<double>* vals2, long size, string prefix) {
	for (long i = 0; i < size; ++i) {
		cout << "---------------------" << endl;
		cout << "m" + prefix + ": " << i << " :" << val1 << endl;
		cout << "d" + prefix + ": " << i << " :" << vals2[i] << endl;
		cout << "e" + prefix + ": " << i << " :" << val1-vals2[i] << endl;
		cout << "---------------------" << endl;
	}
}