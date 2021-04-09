/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#ifndef HEAAN_SCHEMEALGO_H_
#define HEAAN_SCHEMEALGO_H_

#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>

#include "EvaluatorUtils.h"
#include "Plaintext.h"
#include "SecretKey.h"
#include "Ciphertext.h"
#include "Scheme.h"

static string LOGARITHM = "Logarithm"; ///< log(x)
static string EXPONENT  = "Exponent"; ///< exp(x)
static string SIGMOID   = "Sigmoid"; ///< sigmoid(x) = exp(x) / (1 + exp(x))
static string SQRT4     = "Sqrt4"; ///< sqrt(x) with deg 4 approximation
static string SQRT5     = "Sqrt5"; ///< sqrt(x) with deg 5 approximation 
static string SQRT6     = "Sqrt6"; ///< sqrt(x) with deg § approximation 
static string SQRT7     = "Sqrt7"; ///< sqrt(x) with deg 7 approximation 
static string SQRT8     = "Sqrt8"; ///< sqrt(x) with deg 8 approximation 
static string SQRT9     = "Sqrt9"; ///< sqrt(x) with deg 9 approximation 
static string SQRT10    = "Sqrt10";///< sqrt(x) with deg 10 approximation 
static string DISTANCE  = "Distance"; ///< sqrt(x) with deg 8 approximation 
static string ENC  = "Ecryption"; ///< Enc 
static string DEC  = "Decryption"; ///< Dec 
static string ZKGEN = "ZK Generate";
static string ZKSPLIT = "ZK Split Secret";
static string ZKSIGN = "ZK Signature";
static string ZKVER = "ZK Verification";

class SchemeAlgo {
public:
	Scheme& scheme;
	map<string, double*> taylorCoeffsMap;

	SchemeAlgo(Scheme& scheme) : scheme(scheme) { //x⁰ -> x^n
		taylorCoeffsMap.insert(pair<string, double*>(LOGARITHM,new double[11] {0,1,-0.5,1./3,-1./4,1./5,-1./6,1./7,-1./8,1./9,-1./10}));
		taylorCoeffsMap.insert(pair<string, double*>(EXPONENT,new double[11] {1,1,0.5,1./6,1./24,1./120,1./720,1./5040,1./40320,1./362880,1./3628800 }));
		taylorCoeffsMap.insert(pair<string, double*>(SIGMOID,new double[11] {1./2,1./4,0,-1./48,0,1./480,0,-17./80640,0,31./1451520,0}));

		// [0,25]
		taylorCoeffsMap.insert(pair<string, double*>(SQRT4,new double[5] {50./99,16./33,-28./825,448./309375,-4./171875})); // [0, 25]
		taylorCoeffsMap.insert(pair<string, double*>(SQRT5,new double[6] {60./143,84./143,-(224./3575),2016./446875,-(72./446875),56./25390625}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT6,new double[7] {14./39,224./325,-(168./1625),448./40625,-(132./203125),2464./126953125,-(56./244140625)}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT7,new double[8] {16./51,336./425,-(336./2125),1232./53125,-(528./265625),16016./166015625,-(10192./4150390625),528./20751953125}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {90./323, 288./323, -1848./8075, 44352./1009375, -5148./1009375, 224224./630859375, -45864./3154296875, 25344./78857421875, -1716./579833984375})); //[0,25]
		taylorCoeffsMap.insert(pair<string, double*>(SQRT9,new double[10] {100./399, 132./133, -1056./3325, 4576./59375, -3432./296875, 8008./7421875, -11648./185546875, 71808./32470703125, -175032./4058837890625, 1144./3204345703125})); //[0,25]
		taylorCoeffsMap.insert(pair<string, double*>(SQRT10,new double[11] {110./483, 176./161, -1716./4025, 9152./71875, -1716./71875, 128128./44921875, -49504./224609375, 430848./39306640625, -1662804./4913330078125, 86944./14739990234375, -19448./438690185546875})); //[0,25]

/*
		// [0.1, 25]
		taylorCoeffsMap.insert(pair<string, double*>(SQRT5,new double[6] {0.513493,0.547332,-0.0553738,0.00390152,-0.000137723,0.00000187161}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT6,new double[7] {0.46481,0.629121,-0.0880892,0.00913598,-0.000530308,0.0000156906,-0.000000184253}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT7,new double[8] {0.430602,0.705747,-0.129467,0.0183311,-0.00154177,0.0000739508,-0.00000186732,0.0000000192351}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {0.408679,0.768885,-0.173664,0.0312955,-0.00348644,0.000235747,-0.00000941782,0.000000204145,-0.0000000018491}));
*/

/*
		// [0.5, 25]
		taylorCoeffsMap.insert(pair<string, double*>(SQRT5,new double[6] {0.784004,0.452613,-0.039539,0.002626,-0.0000898696,0.00000119846}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT6,new double[7] {0.756511,0.4988,-0.0580137,0.00558196,-0.000311567,0.0000090022,-0.00000010405}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT7,new double[8] {0.739544,0.536807,-0.0785374,0.0101428,-0.000813257,0.0000378996,-0.000000938863,0.00000000954073}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {0.728755,0.567879,-0.100288,0.016523,-0.00177029,0.000117525,-0.00000465471,0.000000100541,-0.000000000910003}));
*/
/*
		// [1, 25]
		taylorCoeffsMap.insert(pair<string, double*>(SQRT5,new double[6] {108151./104247,110452./289575,-(626216./21718125),2939296./1628859375,-(162592./2714765625),896./1142578125}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT6,new double[7] {435553./426465,1451908./3553875,-(141016./3553875),1572512./444234375,-(140704./740390625),2482816./462744140625,-(163072./2669677734375)}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT7,new double[8] {20911./20655,5974396./13942125,-(1172632./23236875),1149536./193640625,-(1317728./2904609375),12435584./605126953125,-(7560448./15128173828125),1137664./226922607421875}));
		taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {6404201./6357609,4695124./10596015,-(595304./9811125),59152288./6622509375,-(49834528./55187578125),399661696./6898447265625,-(1161203456./517383544921875),68609024./1437176513671875,-(2708992./6340484619140625)}));
*/

		// deg 8 [0,2] - not good
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {18/323, 1440/323, -9240/323, 44352/323, -128700/323, 224224/323, -229320/323, 126720/323, -1716/19})); // [0,1]})); // [0,2]

		// deg 8 [0,1] - not really precise
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT10,new double[11] {22./483, 880./161, -8580./161, 9152./23, -42900./23, 128128./23, -247520./23, 2154240./161, -1662804./161, 2173600./483, -19448./23}));
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT9,new double[10] {20./399, 660./133, -5280./133, 4576./19, -17160./19, 40040./19, -58240./19, 359040./133, -175032./133, 5720./21}));
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {18/323, 1440/323, -9240/323, 44352/323, -128700/323, 224224/323, -229320/323, 126720/323, -1716/19})); // [0,1]

		// deg 8 [0,100] - OK but overshoots
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT10,new double[11] {220/483, 88./161, -429./8050, 286./71875, -429./2300000, 1001./179687500, -1547./14375000000, 1683./1257812500000, -415701./40250000000000000, 2717./60375000000000000, -2431./28750000000000000000}));
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT9,new double[10] {200./399, 66./133, -132./3325, 143./59375, -429./4750000, 1001./475000000, -91./2968750000, 561./2078125000000, -21879./16625000000000000, 143./52500000000000000}));
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {180./323, 144./323, -231./8075, 1386./1009375, -1287./32300000, 7007./10093750000, -5733./807500000000, 99./2523437500000, -429./4750000000000000 })); //[0,100]

		// [0,1000]
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT4,new double[5] {3.19422, 0.0766613, -0.000134157, 0.000000143101, -.000000000057496}));
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {1.76226, 0.140981, -0.000904627,0.00000434221,-0.0000000126002,0.0000000000219523, -0.0000000000000224512, 0.000000392322 }));
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT9,new double[10] {200*sqrt(10)/399, 22*sqrt(2/5)/133, -33*sqrt(2/5)/16625, 143./(5937500*sqrt(10)), -429./(4750000000*sqrt(10)), 1001./(4750000000000*sqrt(10)), -91./(296875000000000*sqrt(10)), 561./(2078125000000000000*sqrt(10)), -21879./(166250000000000000000000*sqrt(10)), 143./(5250000000000000000000000*sqrt(10))}));
		//taylorCoeffsMap.insert(pair<string, double*>(SQRT8,new double[9] {180*sqrt(10)/323, 72*sqrt(2/5)/323, -232./(80750*sqrt(10)), 693./(50468750*sqrt(10)), -1287./(32300000000*sqrt(10)), 7007./(100937500000000*sqrt(10)), -5733./(80750000000000000*sqrt(10)), 99./(2523437500000000000*sqrt(10)), -7293./(47500000000000000000000*sqrt(10))}));
	

	};


	void powerOf2(Ciphertext& res, Ciphertext& cipher, long precisionBits, long logDegree);

	void powerOf2Extended(Ciphertext* res, Ciphertext& cipher, long logp, long logDegree);

	void power(Ciphertext& res, Ciphertext& cipher, long logp, long degree);

	void powerExtended(Ciphertext* res, Ciphertext& cipher, long logp, long degree);

	void inverse(Ciphertext& res, Ciphertext& cipher, long logp, long steps);

	void function(Ciphertext& res, Ciphertext& cipher, string& funcName, long logp, long degree);

	void functionLazy(Ciphertext& res, Ciphertext& cipher, string& funcName, long logp, long degree);

};

#endif
