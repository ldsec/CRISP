/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "TestScheme.h"

#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <complex>

#include "Ciphertext.h"
#include "EvaluatorUtils.h"
#include "Ring.h"
#include "Scheme.h"
#include "SchemeAlgo.h"
#include "SecretKey.h"
#include "StringUtils.h"
#include "TimeUtils.h"
#include "SerializationUtils.h"

using namespace std;
using namespace NTL;


//----------------------------------------------------------------------------------
//   STANDARD TESTS
//----------------------------------------------------------------------------------


void TestScheme::testEncrypt(long logq, long logp, long logn) {
	cout << "!!! START TEST ENCRYPT !!!" << endl;
	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;

	timeutils.start("Encrypt");
	scheme.encrypt(cipher, mvec, n, logp, logq);
	timeutils.stop("Encrypt");

	timeutils.start("Decrypt");
	complex<double>* dvec = scheme.decrypt(secretKey, cipher);
	timeutils.stop("Decrypt");

	StringUtils::compare(mvec, dvec, n, "val");

	cout << "!!! END TEST ENCRYPT !!!" << endl;
}

void TestScheme::testEncryptSingle(long logq, long logp) {
	cout << "!!! START TEST ENCRYPT SINGLE !!!" << endl;
	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	complex<double> mval = EvaluatorUtils::randomComplex();
	Ciphertext cipher;

	timeutils.start("Encrypt Single");
	scheme.encryptSingle(cipher, mval, logp, logq);
	timeutils.stop("Encrypt Single");

	complex<double> dval = scheme.decryptSingle(secretKey, cipher);

	StringUtils::compare(mval, dval, "val");

	cout << "!!! END TEST ENCRYPT SINGLE !!!" << endl;
}

void TestScheme::testAdd(long logq, long logp, long logn) {
	cout << "!!! START TEST ADD !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* madd = new complex<double>[n];

	for(long i = 0; i < n; i++) {
		madd[i] = mvec1[i] + mvec2[i];
	}

	Ciphertext cipher1, cipher2;
	scheme.encrypt(cipher1, mvec1, n, logp, logq);
	scheme.encrypt(cipher2, mvec2, n, logp, logq);

	timeutils.start("Addition");
	scheme.multAndEqual(cipher1, cipher2);
	timeutils.stop("Addition");

	complex<double>* dadd = scheme.decrypt(secretKey, cipher1);

	//StringUtils::showVec(mvec1, n);
	//StringUtils::showVec(mvec2, n);
	//<StringUtils::showVec(madd, n);

	StringUtils::compare(madd, dadd, n, "add");

	cout << "!!! END TEST ADD !!!" << endl;
}

void TestScheme::testMult(long logq, long logp, long logn) {
	cout << "!!! START TEST MULT !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mmult = new complex<double>[n];

	StringUtils::showVec(mvec1, n);
	StringUtils::showVec(mvec2, n);

	for(long i = 0; i < n; i++) {
		mmult[i] = mvec1[i] * mvec2[i];
	}

	Ciphertext cipher1, cipher2;
	scheme.encrypt(cipher1, mvec1, n, logp, logq);
	scheme.encrypt(cipher2, mvec2, n, logp, logq);

	timeutils.start("Multiplication");
	scheme.multAndEqual(cipher1, cipher2);
	timeutils.stop("Multiplication");

	complex<double>* dmult = scheme.decrypt(secretKey, cipher1);

	StringUtils::showVec(mmult, n);

	StringUtils::compare(mmult, dmult, n, "mult");

	cout << "!!! END TEST MULT !!!" << endl;
}

void TestScheme::testimult(long logq, long logp, long logn) {
	cout << "!!! START TEST i MULTIPLICATION !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* imvec = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		imvec[i].real(-mvec[i].imag());
		imvec[i].imag(mvec[i].real());
	}

	StringUtils::showVec(mvec, n);
	StringUtils::showVec(imvec, n);

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Multiplication by i");
	scheme.imultAndEqual(cipher);
	timeutils.stop("Multiplication by i");

	complex<double>* idvec = scheme.decrypt(secretKey, cipher);

	StringUtils::compare(imvec, idvec, n, "imult");

	cout << "!!! END TEST i MULTIPLICATION !!!" << endl;
}


//----------------------------------------------------------------------------------
//   ROTATE & CONJUGATE
//----------------------------------------------------------------------------------


void TestScheme::testRotateFast(long logq, long logp, long logn, long logr) {
	cout << "!!! START TEST ROTATE FAST !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	long n = (1 << logn);
	long r = (1 << logr);
	scheme.addLeftRotKey(secretKey, r);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Left Rotate Fast");
	scheme.leftRotateFastAndEqual(cipher, r);
	timeutils.stop("Left Rotate Fast");

	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	StringUtils::showVec(mvec, n);

	EvaluatorUtils::leftRotateAndEqual(mvec, n, r);

	StringUtils::showVec(mvec, n);
	//StringUtils::showVec(mvec, n);
	//StringUtils::showVec(dvec, n);
	StringUtils::compare(mvec, dvec, n, "rot");

	cout << "!!! END TEST ROTATE BY POWER OF 2 BATCH !!!" << endl;
}

void TestScheme::testConjugate(long logq, long logp, long logn) {
	cout << "!!! START TEST CONJUGATE !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	scheme.addConjKey(secretKey);

	long n = (1 << logn);

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	complex<double>* mvecconj = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvecconj[i] = conj(mvec[i]);
	}

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Conjugate");
	scheme.conjugateAndEqual(cipher);
	timeutils.stop("Conjugate");

	complex<double>* dvecconj = scheme.decrypt(secretKey, cipher);
	StringUtils::showVec(mvec, n);
	StringUtils::showVec(mvecconj, n);
	StringUtils::compare(mvecconj, dvecconj, n, "conj");

	cout << "!!! END TEST CONJUGATE !!!" << endl;
}


//----------------------------------------------------------------------------------
//   POWER & PRODUCT TESTS
//----------------------------------------------------------------------------------


void TestScheme::testPowerOf2(long logq, long logp, long logn, long logdeg) {
	cout << "!!! START TEST POWER OF 2 !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	long degree = 1 << logdeg;
	complex<double>* mvec = new complex<double>[n];
	//cout << "mvec and mpow 2^" << logdeg << endl;
	complex<double>* mpow = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvec[i] = EvaluatorUtils::randomCircle();
		mpow[i] = pow(mvec[i], degree);
	}
	//StringUtils::showVec(mvec, n);
	//StringUtils::showVec(mpow, n);

	Ciphertext cipher, cpow;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Power of 2");
	algo.powerOf2(cpow, cipher, logp, logdeg);
	timeutils.stop("Power of 2");

	complex<double>* dpow = scheme.decrypt(secretKey, cpow);
	StringUtils::compare(mpow, dpow, n, "pow2");

	cout << "!!! END TEST POWER OF 2 !!!" << endl;
}

//-----------------------------------------

void TestScheme::testPower(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST POWER !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomCircleArray(n);
	cout << "mvec and mpow ^"<< degree << endl;
	StringUtils::showVec(mvec, n);

	complex<double>* mpow = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mpow[i] = pow(mvec[i], degree);
	}
	StringUtils::showVec(mpow, n);

	Ciphertext cipher, cpow;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Power");
	algo.power(cpow, cipher, logp, degree);
	timeutils.stop("Power");

	complex<double>* dpow = scheme.decrypt(secretKey, cpow);
	StringUtils::compare(mpow, dpow, n, "pow");

	cout << "!!! END TEST POWER !!!" << endl;
}


//----------------------------------------------------------------------------------
//   FUNCTION TESTS
//----------------------------------------------------------------------------------


void TestScheme::testInverse(long logq, long logp, long logn, long steps) {
	cout << "!!! START TEST INVERSE !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomCircleArray(n, 0.1);
	//cout << "mvec and minv" << endl;
	//StringUtils::showVec(mvec, n);
	complex<double>* minv = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		minv[i] = 1. / mvec[i];
	}
	//StringUtils::showVec(minv, n);
	
	Ciphertext cipher, cinv;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start("Inverse");
	algo.inverse(cinv, cipher, logp, steps);
	timeutils.stop("Inverse");

	complex<double>* dinv = scheme.decrypt(secretKey, cinv);
	StringUtils::compare(minv, dinv, n, "inv");

	cout << "!!! END TEST INVERSE !!!" << endl;
}

void TestScheme::testLogarithm(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST LOGARITHM !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n, 0.1);
	//cout << "mvec and mlog" << endl;
	//StringUtils::showVec(mvec, n);
	complex<double>* mlog = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mlog[i] = log(mvec[i] + 1.);
	}
	//StringUtils::showVec(mlog, n);

	Ciphertext cipher, clog;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(LOGARITHM);
	algo.function(clog, cipher, LOGARITHM, logp, degree);
	timeutils.stop(LOGARITHM);

	complex<double>* dlog = scheme.decrypt(secretKey, clog);
	StringUtils::compare(mlog, dlog, n, LOGARITHM);

	cout << "!!! END TEST LOGARITHM !!!" << endl;
}

void TestScheme::testExponent(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST EXPONENT !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	//cout << "mvec and mexp" << endl;
	//StringUtils::showVec(mvec, n);
	complex<double>* mexp = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mexp[i] = exp(mvec[i]);
	}
	//StringUtils::showVec(mexp, n);

	Ciphertext cipher, cexp;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(EXPONENT);
	algo.function(cexp, cipher, EXPONENT, logp, degree);
	timeutils.stop(EXPONENT);

	complex<double>* dexp = scheme.decrypt(secretKey, cexp);
	StringUtils::compare(mexp, dexp, n, EXPONENT);

	cout << "!!! END TEST EXPONENT !!!" << endl;
}



void TestScheme::testSqrt4(long logq, long logp, long logn) {
	cout << "!!! START TEST SQRT4 !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n, 20); // get a rdm vector in [0, 20]^n
	complex<double>* msqrt = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvec[i]  = complex<double>(mvec[i].real(), 0);
		msqrt[i] = complex<double>(sqrt(abs(mvec[i].real())), sqrt(abs(mvec[i].imag())));
	}
	StringUtils::showVec(mvec, n);

	Ciphertext cipher, csqrt;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SQRT4);
	algo.function(csqrt, cipher, SQRT4, logp, 5);
	timeutils.stop(SQRT4);

	complex<double>* dsqrt = scheme.decrypt(secretKey, csqrt);
	//StringUtils::showVec(dsqrt, n);
	StringUtils::compare(msqrt, dsqrt, n, SQRT4);	

	cout << "!!! END TEST SQRT4 !!!" << endl;
}


void TestScheme::testSqrt8(long logq, long logp, long logn) {
	cout << "!!! START TEST SQRT8 !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n, 12); // get a rdm vector in [0, 12]^n
	complex<double>* msqrt = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvec[i]  = complex<double>(mvec[i].real(), 0.);
		msqrt[i] = complex<double>(sqrt(abs(mvec[i].real())), sqrt(abs(mvec[i].imag())));
	}

	Ciphertext cipher, csqrt;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SQRT8);
	algo.function(csqrt, cipher, SQRT8, logp, 9);
	timeutils.stop(SQRT8);

	complex<double>* dsqrt = scheme.decrypt(secretKey, csqrt);
	StringUtils::compare(msqrt, dsqrt, n, SQRT8);

	cout << "!!! END TEST SQRT8 !!!" << endl;
}



void TestScheme::testAllSqrt(long logq, long logp, long logn) {
	cout << "!!! START TEST SQRT8 !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n, 10); // get a rdm vector in [0, 12]^n
	complex<double>* msqrt = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mvec[i]  = complex<double>(mvec[i].real(), 0.);
		msqrt[i] = complex<double>(sqrt(abs(mvec[i].real())), sqrt(abs(mvec[i].imag())));
	}

	Ciphertext cipher, csqrt, csqrt2;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SQRT8);
	algo.function(csqrt, cipher, SQRT8, logp, 9);
	timeutils.stop(SQRT8);

	timeutils.start(SQRT8);
	Ciphertext cipher2;

	scheme.square(cipher2, cipher);
	//cout << "c2_logQ = "<<cipher2.logq << endl;

	scheme.reScaleByAndEqual(cipher2, logp); // cipher2.logq : logq - logp
	//cout << "c2_logQ = "<<cipher2.logq << endl;

	Ciphertext cipher4;
	scheme.square(cipher4, cipher2);
	//cout << "c4_logQ = "<<cipher4.logq << endl;
	scheme.reScaleByAndEqual(cipher4, logp); // cipher4.logq : logq -2logp
	//cout << "c4_logQ = "<<cipher4.logq << endl;

	Ciphertext cipher8;
	scheme.square(cipher8, cipher4);
	//cout << "c8_logQ = "<<cipher8.logq << endl;
	scheme.reScaleByAndEqual(cipher8, logp); // cipher4.logq : logq -2logp
	//cout << "c8_logQ = "<<cipher8.logq << endl;

	RR c;
	c =  45./144; //a0/a1
	Ciphertext cipher01;
	scheme.addConst(cipher01, cipher, c, logp); 
	//cout << "cip1_logQ = "<<cipher01.logq << endl;


	c = 288./323; //a1
	scheme.multByConstAndEqual(cipher01, c, logp);
	//cout << "cip1_logQ = "<<cipher01.logq << endl;
	scheme.reScaleByAndEqual(cipher01, logp); 
	//cout << "cip1_logQ = "<<cipher01.logq << endl;

	c = -125./24; //a2/a3
	Ciphertext cipher23;
	scheme.addConst(cipher23, cipher, c, logp); 
	//cout << "cip23_logQ = "<<cipher23.logq << endl;

	c = 44352./1009375;//a3
	scheme.multByConstAndEqual(cipher23, c, logp);
	//cout << "cip23_logQ = "<<cipher23.logq << endl;
	scheme.reScaleByAndEqual(cipher23, logp);
	//cout << "cip23_logQ = "<<cipher23.logq << endl;

	scheme.multAndEqual(cipher23, cipher2);
	//cout << "cip23_logQ = "<<cipher23.logq << endl;
	scheme.reScaleByAndEqual(cipher23, logp); 
	//cout << "cip23_logQ = "<<cipher23.logq << endl;

	scheme.addAndEqual(cipher23, cipher01); 
	//cout << "cip23_logQ = "<<cipher23.logq << endl;

	c = -5625./392; //a4/a5
	Ciphertext cipher45;
	scheme.addConst(cipher45, cipher, c, logp); 
	//cout << "cip45_logQ = "<<cipher45.logq << endl;

	c = 224224./630859375; //a5
	scheme.multByConstAndEqual(cipher45, c, logp);
	//cout << "cip45_logQ = "<<cipher45.logq << endl;
	scheme.reScaleByAndEqual(cipher45, logp); 
	//cout << "cip45_logQ = "<<cipher45.logq << endl;

	c = -15925./352; // a6/a7
	scheme.addConstAndEqual(cipher, c, logp); 
	//cout << "cip_logQ = "<<cipher.logq << endl;

	c = 25344./78857421875; // a7
	scheme.multByConstAndEqual(cipher, c, logp);
	//cout << "cip_logQ = "<<cipher.logq << endl;
	scheme.reScaleByAndEqual(cipher, logp); 
	//cout << "cip_logQ = "<<cipher.logq << endl;

	scheme.multAndEqual(cipher, cipher2);
	//cout << "cip_logQ = "<<cipher.logq << endl;
	scheme.reScaleByAndEqual(cipher, logp); 
	//cout << "cip_logQ = "<<cipher.logq << endl;

	scheme.modDownByAndEqual(cipher45, logp); 
	//cout << "cip_logQ = "<<cipher.logq << endl;
	scheme.addAndEqual(cipher, cipher45); 
	//cout << "cip_logQ = "<<cipher.logq << endl;

	scheme.multAndEqual(cipher, cipher4);
	//cout << "cip_logQ = "<<cipher.logq << endl;
	scheme.reScaleByAndEqual(cipher, logp); 
	//cout << "cip_logQ = "<<cipher.logq << endl;

	scheme.modDownByAndEqual(cipher23, logp);
	scheme.addAndEqual(cipher, cipher23); 
	//cout << "cip_logQ = "<<cipher.logq << endl;
	
	c = -1716./579833984375; //a8
	scheme.multByConstAndEqual(cipher8, c, logp);
	scheme.reScaleByAndEqual(cipher8, logp); 
	scheme.addAndEqual(cipher, cipher8);
	timeutils.stop(SQRT8);


	complex<double>* dsqrt = scheme.decrypt(secretKey, csqrt);
	complex<double>* dsqrt2 = scheme.decrypt(secretKey, cipher);
	StringUtils::compare(msqrt, dsqrt, n, SQRT8);
	cout<<" "<<endl;
	StringUtils::compare(msqrt, dsqrt2, n, SQRT8);


	cout << "!!! END TEST SQRT8 !!!" << endl;
}


void TestScheme::testExponentLazy(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST EXPONENT LAZY !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	//cout << "mvec and mexp" << endl;
	//StringUtils::showVec(mvec, n);
	complex<double>* mexp = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		mexp[i] = exp(mvec[i]);
	}
	//StringUtils::showVec(mexp, n);

	Ciphertext cipher, cexp;
	scheme.encrypt(cipher, mvec, n, logp, logQ);

	timeutils.start(EXPONENT + " lazy");
	algo.functionLazy(cexp, cipher, EXPONENT, logp, degree);
	timeutils.stop(EXPONENT + " lazy");

	complex<double>* dexp = scheme.decrypt(secretKey, cexp);
	StringUtils::compare(mexp, dexp, n, EXPONENT);

	cout << "!!! END TEST EXPONENT LAZY !!!" << endl;
}

//-----------------------------------------

void TestScheme::testSigmoid(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST SIGMOID !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;

	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	//cout << "mvec and msig" << endl;
	//StringUtils::showVec(mvec, n);
	complex<double>* msig = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		msig[i] = exp(mvec[i]) / (1. + exp(mvec[i]));
	}
	//StringUtils::showVec(msig, n);

	Ciphertext cipher, csig;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SIGMOID);
	algo.function(csig, cipher, SIGMOID, logp, degree);
	timeutils.stop(SIGMOID);

	complex<double>* dsig = scheme.decrypt(secretKey, csig);
	StringUtils::compare(msig, dsig, n, SIGMOID);

	cout << "!!! END TEST SIGMOID !!!" << endl;
}

void TestScheme::testSigmoidLazy(long logq, long logp, long logn, long degree) {
	cout << "!!! START TEST SIGMOID LAZY !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = 1 << logn;
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(n);
	//cout << "mvec and msig" << endl;
	//StringUtils::showVec(mvec, n);
	complex<double>* msig = new complex<double>[n];
	for (long i = 0; i < n; ++i) {
		msig[i] = exp(mvec[i]) / (1. + exp(mvec[i]));
	}
	//StringUtils::showVec(msig, n);

	Ciphertext cipher, csig;
	scheme.encrypt(cipher, mvec, n, logp, logq);

	timeutils.start(SIGMOID + " lazy");
	algo.functionLazy(csig, cipher, SIGMOID, logp, degree);
	timeutils.stop(SIGMOID + " lazy");

	complex<double>* dsig = scheme.decrypt(secretKey, csig);
	StringUtils::compare(msig, dsig, n, SIGMOID);

	cout << "!!! END TEST SIGMOID LAZY !!!" << endl;
}


void TestScheme::testDistance(long logq, long logp, long logn, complex<double>* mvec, complex<double>* mbin, complex<double>* mDes, int points, int norm, double realDistance) {
	cout << "!!! START DISTANCE !!!" << endl;
	srand(time(NULL));
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);
	SchemeAlgo algo(scheme);

	long n = (1 << logn);
	long r = (1 << 0);
	scheme.addLeftRotKey(secretKey, r);
	long r2 = n/2;
	scheme.addLeftRotKey(secretKey, r2);


	timeutils.start(ENC);
	//* Encrypt the plaintext
	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, n, logp, logq);
	timeutils.stop(ENC);


	timeutils.start(DISTANCE);
	//* Create the difference vector
	Ciphertext diff;
	scheme.leftRotateFast(diff, cipher, r);
	scheme.subAndEqual(cipher, diff);

	//* Distroy elements in slot point and n/2+point
	Ciphertext cbin;
	scheme.encrypt(cbin, mbin, n, logp, logq);//encode(plain, vals, n, logp, logq);
	scheme.multAndEqual(cipher, cbin);
	scheme.reScaleByAndEqual(cipher, logp);

	Plaintext plnBin;

	//* Square each slot 
	scheme.squareAndEqual(cipher);
	scheme.reScaleByAndEqual(cipher, logp);

	//* Sum subdistances
	Ciphertext subd;
	scheme.leftRotateFast(subd, cipher, r2);
	scheme.addAndEqual(cipher, subd);
	complex<double>* tmp10 = scheme.decrypt(secretKey, cipher);	
	

	// Check range for square root
	for (long i = 0; i < points-1; ++i) {
			if (tmp10[i].real()>9){
			cout<<"distance "<<i<<" out of sqrt range : "<<tmp10[i].real()<<endl;
		}
			if (tmp10[i].real()<0.2){
			cout<<"distance "<<i<<" out of sqrt range inf : "<<tmp10[i].real()<<endl;
		}
	}

	//* Take square root of each slot
	Ciphertext csqrt;
	algo.function(csqrt, cipher, SQRT8, logp, 9); //SQRT9

	///* Show The subdistance vector
	complex<double>* dm = scheme.decrypt(secretKey, csqrt);	

	///* Remove non necessary slots before summation
	Ciphertext cDes;
	scheme.encrypt(cDes, mDes, n, logp, logq);
	scheme.multAndEqual(csqrt, cDes);
	scheme.reScaleByAndEqual(csqrt, logp);


	///* Sum to slot 0
	for (long j =0; j< log(points-1)/log(2); j++) {
		Ciphertext rot;
		scheme.addLeftRotKey(secretKey, pow(2,j));
		scheme.leftRotateFast(rot, csqrt, pow(2,j));
		scheme.addAndEqual(csqrt, rot);
		//cout << "sum logq = "<<csqrt.logq << endl;
	}
	timeutils.stop(DISTANCE);

	//cout << "sum logq = "<<csqrt.logq << endl;

	// DECRYPTION 
	timeutils.start(DEC);
	///* Decrypt 
	complex<double>* decDir = scheme.decrypt(secretKey, csqrt);
	timeutils.stop(DEC);
	cout<<"distance = "<<decDir[0].real()*norm<<endl;

	double distance = 0;
	for (long i = 0; i < points-1; ++i) {
		distance += dm[i].real();
	}

	// Print for Latex
	// log n  | logq  |  logp  | RealDist | Distance  | error | t_i
	double result = decDir[0].real()*norm;
	cout<< logn <<" & "<< logq <<" & "<< logp <<" & "<< points <<" & "<<realDistance <<" & "<< decDir[0].real()*norm <<" & "<< distance*norm <<" & "<< floor((result*100./realDistance -100)*100)/100;//<<" & "<< floor(tenc/10)/100 <<" & "<< floor(tdist/10)/100 <<" & " << floor(tdec)/1000<<" & "<<counter;


}




void TestScheme::testWriteAndRead(long logq, long logp, long logSlots) {
	cout << "!!! START TEST WRITE AND READ !!!" << endl;

	cout << "!!! END TEST WRITE AND READ !!!" << endl;
}


void TestScheme::testBootstrap(long logq, long logQ, long logp, long logSlots, long logT) {
	/**
	 * Testing bootstrapping procedure for single real value
	 * number of modulus bits up: depends on parameters
	 * @param[in] logN: input parameter for Params class
	 * @param[in] logq: log of initial modulus
	 * @param[in] logQ: input parameter for Params class
	 * @param[in] logSlots: log of number of slots
	 * @param[in] nu: auxiliary parameter, corresonds to message bits (message bits is logq - nu)
	 * @param[in] logT: auxiliary parameter, corresponds to number of iterations in removeIpart (num of iterations is logI + logT)
	 * testBootstrap(long logq, long logQ, long logp, long logn, long logT); as of Nov18

	 */


	cout << "!!! START TEST BOOTSTRAP !!!" << endl;

	srand(time(NULL));
	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	timeutils.start("Key generating");
	scheme.addBootKey(secretKey, logSlots, logq + 4);
	timeutils.stop("Key generated");

	long slots = (1 << logSlots);
	complex<double>* mvec = EvaluatorUtils::randomComplexArray(slots);

	Ciphertext cipher;
	scheme.encrypt(cipher, mvec, slots, logp, logq);

	cout << "cipher logq before: " << cipher.logq << endl;

	scheme.modDownToAndEqual(cipher, logq);
	scheme.normalizeAndEqual(cipher);
	cipher.logq = logQ;
	cipher.logp = logq + 4;

	Ciphertext rot;
	timeutils.start("SubSum");
	for (long i = logSlots; i < logNh; ++i) {
		scheme.leftRotateFast(rot, cipher, (1 << i));
		scheme.addAndEqual(cipher, rot);
	}
	scheme.divByPo2AndEqual(cipher, logNh);
	timeutils.stop("SubSum");

	timeutils.start("CoeffToSlot");
	scheme.coeffToSlotAndEqual(cipher); // Issue here with default parameters
	timeutils.stop("CoeffToSlot");

	timeutils.start("EvalExp");
	scheme.evalExpAndEqual(cipher, logT);
	timeutils.stop("EvalExp");

	timeutils.start("SlotToCoeff");
	scheme.slotToCoeffAndEqual(cipher);
	timeutils.stop("SlotToCoeff");

	cipher.logp = logp;
	cout << "cipher logq after: " << cipher.logq << endl;

	complex<double>* dvec = scheme.decrypt(secretKey, cipher);

	StringUtils::compare(mvec, dvec, slots, "boot");

	cout << "!!! END TEST BOOTSRTAP !!!" << endl;
}

void TestScheme::testBootstrapSingleReal(long logq, long logQ, long logp, long logT) {
	cout << "!!! START TEST BOOTSTRAP SINGLE REAL !!!" << endl;

	srand(time(NULL));
//	SetNumThreads(8);
	TimeUtils timeutils;
	Ring ring;
	SecretKey secretKey(ring);
	Scheme scheme(secretKey, ring);

	timeutils.start("Key generating");
	scheme.addBootKey(secretKey, 0, logq + 4);
	timeutils.stop("Key generated");

	cout << "key ok" << endl;

	double mval = EvaluatorUtils::randomReal();

	Ciphertext cipher;
	scheme.encryptSingle(cipher, mval, logp, logq);

	cout << "cipher logq before: " << cipher.logq << endl;
	scheme.modDownToAndEqual(cipher, logq);
	scheme.normalizeAndEqual(cipher);
	cipher.logq = logQ;

	Ciphertext rot, cconj;
	timeutils.start("SubSum");
	for (long i = 0; i < logNh; ++i) {
		scheme.leftRotateFast(rot, cipher, 1 << i);
		scheme.addAndEqual(cipher, rot);
	}
	scheme.conjugate(cconj, cipher);
	scheme.addAndEqual(cipher, cconj);
	scheme.divByPo2AndEqual(cipher, logN);
	timeutils.stop("SubSum");

	timeutils.start("EvalExp");
	scheme.evalExpAndEqual(cipher, logT);
	timeutils.stop("EvalExp");

	cout << "cipher logq after: " << cipher.logq << endl;

	cipher.logp = logp;
	complex<double> dval = scheme.decryptSingle(secretKey, cipher);

	StringUtils::compare(mval, dval.real(), "boot");

	cout << "!!! END TEST BOOTSRTAP SINGLE REAL !!!" << endl;
}



void TestScheme::test() {
}

