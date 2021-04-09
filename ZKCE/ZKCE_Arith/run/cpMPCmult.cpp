#include "../src/HEAAN.h"
#include "../src/Params.h"
#include "../src/Scheme.h"
#include "../src/Ring.h"
#include "../src/StringUtils.h"
#include "../src/SerializationUtils.h"
#include "openssl/sha.h"
#include <string>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <fstream>


using namespace std;
using namespace NTL;

typedef unsigned char uchar;
typedef unsigned int uint32;

// b_i = [y_(e_i+2), C_(e_i+2)], where the value from C ist stored directly
typedef struct {
  ZZ** y_e2_;
  string H_k_View_;
} B;

// z_i = [View_i+1, k_i, k_i+1, x_3] where e = i, + key_shares + y share
typedef struct {
  ZZ** y_i_;
  int kz_1_;
  int kz_2_;
  complex<double>* mvec_;
  ZZ* vx_;
  ZZ* m0_;
  ZZ* m1_;
  ZZ** rv_;
  ZZ** rm0_;
  ZZ** rm1_;
} Z;

typedef struct {
  ZZ* VX = new ZZ[N];
  ZZ* M1 = new ZZ[N];
  ZZ* M0 = new ZZ[N];
  ZZ* MX[3] = {new ZZ[N], new ZZ[N], new ZZ[N]};
  ZZ* Rcom[3] = {new ZZ[N], new ZZ[N], new ZZ[N]};
  ZZ* Ccom[4] = {new ZZ[N], new ZZ[N], new ZZ[N], new ZZ[N]};
  complex<double>* mvec;
  Plaintext plain;
  Ciphertext cipher;
} Player;

// This struct is returned from ZKBOO to the user (and can be used with ZKBPP::Verify(.))
// Proof contains the challenge E, all b_i's and all z_i's (i for iteration)
// p = [e, (b_1, z_1), ..., (b_t, z_t)]
typedef struct {
  uint32 num_iterations_;
  uint32 e_;
  ZZ** y_e2_;
  string H_k_View_;
  Z zs_;
 } Proof;

void commit(ZZ* C[2], ZZ* mx, ZZ* r[3], ZZ* A1[3], ZZ* A2[3], Ring ring, long np,ZZ QQ) {
  ZZ* tmp = new ZZ[N];
  ZZ* tmp1 = new ZZ[N];

  /// ->> C1
  ring.mult(tmp, A1[1], r[1], np, QQ);
  ring.mult(tmp1, A1[2], r[2], np, QQ);
  ring.add(C[0], tmp, tmp1, QQ);
  ring.addAndEqual(C[0], r[0], QQ);

  /// ->> C2
  ring.mult(tmp, A2[2], r[2], np, QQ);
  ring.addAndEqual(tmp, r[1], QQ);
  ring.add(C[1], tmp, mx, QQ);
}

void commitVec(ZZ* C[4], ZZ* mx[3], ZZ* r[3], ZZ* A[5], Ring ring, long np,ZZ QQ) {
  ZZ* tmp = new ZZ[N];
  ZZ* tmp1 = new ZZ[N];

  /// ->> C1
  ring.mult(tmp, A[0], r[1], np, QQ);
  ring.mult(tmp1, A[1], r[2], np, QQ);
  ring.add(C[0], tmp, tmp1, QQ);
  ring.addAndEqual(C[0], r[0], QQ);

  /// ->> C2
  ring.mult(tmp, A[2], r[2], np, QQ);
  ring.addAndEqual(tmp, r[1], QQ);
  ring.add(C[1], tmp, mx[0], QQ);
  
  /// ->> C2
  ring.mult(tmp, A[3], r[2], np, QQ);
  ring.addAndEqual(tmp, r[1], QQ);
  ring.add(C[2], tmp, mx[1], QQ);

  /// ->> C2
  ring.mult(tmp, A[4], r[2], np, QQ);
  ring.addAndEqual(tmp, r[1], QQ);
  ring.add(C[3], tmp, mx[2], QQ);
}

void genMatrices( ZZ* r[3], ZZ* A1[3], ZZ* A2[3], Ring ring, long np, ZZ QQ) {
  for (int i; i<3; i++){
    ring.sampleUniform2(A1[i], logQQ); 
  }
  for (int i; i<3; i++){
    ring.sampleUniform2(A2[i], logQQ); 
  }
  for (int i; i<3; i++){
    ring.sampleUniform2(r[i], logQQ); 
  }
}

void genMatricesVec( ZZ* r[3], ZZ* A[5], Ring ring, long np, ZZ QQ) {
  for (int i; i<5; i++){
    ring.sampleUniform2(A[i], logQQ); 
  }
  for (int i; i<3; i++){
    ring.sampleUniform2(r[i], logQQ); 
  }
}

void encrypt(Ciphertext* cipher, Plaintext* plain, Ring ring, Key* key, long n, long logp, long logq, long np, ZZ* vx, ZZ* m0, ZZ* m1) {
  cipher->logp = plain->logp;
  cipher->logq = plain->logq;
  cipher->n = plain->n;
  ZZ qQ = ring.qpows[plain->logq + logQ];
  ring.multNTT(cipher->ax, vx, key->rax, np, qQ);
  ring.addAndEqual(cipher->ax, m1, qQ); // m1 _______
  ring.multNTT(cipher->bx, vx, key->rbx, np, qQ);
  ring.addAndEqual(cipher->bx, m0, qQ); // m0 ________
  ring.addAndEqual(cipher->bx, plain->mx, qQ);
  ring.rightShiftAndEqual(cipher->ax, logQ);
  ring.rightShiftAndEqual(cipher->bx, logQ);
}

string sha256(const string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

string comToString(ZZ** r, long n) {
  return StringUtils::toString(r[0], n) + StringUtils::toString(r[1], n) + StringUtils::toString(r[2], n);
}

string comToString(ZZ** r, long n, int k) {
  string res;
  for (int i=0; i<k; i++) {
    res += StringUtils::toString(r[i], n);
  }
  return res; 
}

string comAllToString(ZZ** rv, ZZ** rm0, ZZ** rm1, long n) {
  return  comToString(rv, n) + comToString(rm0, n) + comToString(rm1, n);
}

string comAllToString(ZZ** rv, ZZ** rm0, ZZ** rm1, long n, int k) {
  return  comToString(rv, n, k) + comToString(rm0, n, k) + comToString(rm1, n, k);
}

void noisedView(Ring ring, ZZ* vx, ZZ* m0, ZZ* m1, ZZ** mx, ZZ** r_com) {  
  ring.sampleUniform2(vx, 4);     /// vx
  ring.sampleUniform2(m0, 4);     /// m0
  ring.sampleUniform2(m1, 4);     /// m1
  ring.sampleUniform2(r_com[0], 4);  /// rv
  ring.sampleUniform2(r_com[1], 4);
  ring.sampleUniform2(r_com[2], 4);
  mx[0] = vx;
  mx[1] = m0;
  mx[2] = m1;
}

void noisedView2(Ring ring, Player player) {  
  ring.sampleUniform2(player.VX, 4);     /// vx
  ring.sampleUniform2(player.M0, 4);     /// m0
  ring.sampleUniform2(player.M1, 4);     /// m1
  ring.sampleUniform2(player.Rcom[0], 4);  /// rv
  ring.sampleUniform2(player.Rcom[1], 4);
  ring.sampleUniform2(player.Rcom[2], 4);
  player.MX[0] = player.VX;
  player.MX[1] = player.M0;
  player.MX[2] = player.M1;
}

void splitNoises(Ring ring, ZZ qQ0, ZZ* vx, ZZ* m0, ZZ* m1, ZZ** mx, ZZ** r_com, ZZ** C_com, ZZ* vx1, ZZ* m01, ZZ* m11, ZZ** mx1, ZZ** r_com1, ZZ** C_com1, ZZ* vx2, ZZ* m02, ZZ* m12, ZZ** mx2, ZZ** r_com2, ZZ** C_com2, ZZ* vx3, ZZ* m03, ZZ* m13, ZZ** mx3, ZZ** r_com3, ZZ** C_com3) {
  ZZ* tmp = new ZZ[N];
  ring.add(tmp, vx1, vx2, qQ0);
  ring.sub(vx3, vx, tmp, qQ0);
  ring.add(tmp, m01, m02, qQ0);
  ring.sub(m03, m0, tmp, qQ0);
  ring.add(tmp, m11, m12, qQ0);
  ring.sub(m13, m1, tmp, qQ0);
  //
  ring.add(tmp, r_com1[0], r_com2[0], qQ0);
  ring.sub(r_com3[0], r_com[0], tmp, qQ0);
  ring.add(tmp, r_com1[1], r_com2[1], qQ0);
  ring.sub(r_com3[1], r_com[1], tmp, qQ0);
  ring.add(tmp, r_com1[2], r_com2[2], qQ0);
  ring.sub(r_com3[2], r_com[2], tmp, qQ0);
  mx3[0] = vx3;
  mx3[1] = m03;
  mx3[2] = m13;
  delete[] tmp;
}

void splitNoises2(Ring ring, ZZ qQ0, Player player0, Player player1, Player player2, Player player3) {
  ZZ* tmp = new ZZ[N];
  ring.add(tmp, player1.VX, player2.VX, qQ0);
  ring.sub(player3.VX, player0.VX, tmp, qQ0);
  ring.add(tmp, player1.M0, player2.M0, qQ0);
  ring.sub(player1.M0, player0.M0, tmp, qQ0);
  ring.add(tmp, player1.M1, player2.M1, qQ0);
  ring.sub(player3.M1, player0.M1, tmp, qQ0);
  //
  ring.add(tmp, player1.Rcom[0], player2.Rcom[0], qQ0);
  ring.sub(player3.Rcom[0], player0.Rcom[0], tmp, qQ0);
  ring.add(tmp, player1.Rcom[1], player2.Rcom[1], qQ0);
  ring.sub(player3.Rcom[1], player0.Rcom[1], tmp, qQ0);
  ring.add(tmp, player1.Rcom[2], player2.Rcom[2], qQ0);
  ring.sub(player3.Rcom[2], player0.Rcom[2], tmp, qQ0);
  player3.MX[0] = player3.VX;
  player3.MX[1] = player3.M0;
  player3.MX[2] = player3.M1;
  delete[] tmp;
}


void encryptInput(Scheme scheme, Ring ring, Ring ring2, Plaintext& plain, Ciphertext& cipher, long logp, long logq, long n, long np, Key* key, complex<double>* mvec, ZZ** A_com, ZZ** mx, ZZ** r_com,  ZZ** C_com, ZZ* vx, ZZ* m0, ZZ* m1, ZZ QQ) {
  scheme.encode(plain, mvec, n, logp, logq);
  encrypt(&cipher, &plain, ring, key, n, logp, logq, np, vx, m0, m1);
  commitVec(C_com, mx, r_com, A_com, ring2, np, QQ);
}

void encryptInput2(Scheme scheme, Ring ring, Ring ring2, long logp, long logq, long n, long np, Key* key, ZZ** A_com, Player player, ZZ QQ) {
  scheme.encode(player.plain, player.mvec, n, logp, logq);
  encrypt(&(player.cipher), &(player.plain), ring, key, n, logp, logq, np, player.VX, player.M0, player.M1);
  commitVec(player.Ccom, player.MX, player.Rcom, A_com, ring2, np, QQ);
}

string* fillContainerC(int k, complex<double>* mvec, ZZ* vx, ZZ* m0, ZZ* m1, ZZ** r_com, ZZ** C_com, Ciphertext cipher, long n) {
  string input = std::to_string(k)+StringUtils::toString(mvec, n)+StringUtils::toString(vx, n)+StringUtils::toString(m0, n)+StringUtils::toString(m1, n);
  string inputCom = comToString(r_com, n);
  string output = StringUtils::toString(cipher.ax, n)+StringUtils::toString(cipher.bx, n);
  string outputCom = StringUtils::toString(C_com[0],n)+StringUtils::toString(C_com[1],n)+StringUtils::toString(C_com[2],n)+StringUtils::toString(C_com[3],n);
  string* res = new string[2];
  res[0] = sha256(input+inputCom+output+outputCom);
  res[1] = output + outputCom;
  return res;
}

string* fillContainerC2(int k, Player player, long n) {
  string input = std::to_string(k)+StringUtils::toString(player.mvec, n)+StringUtils::toString(player.VX, n)+StringUtils::toString(player.M0, n)+StringUtils::toString(player.M1, n);
  string inputCom = comToString(player.Rcom, n);
  string output = StringUtils::toString(player.cipher.ax, n)+StringUtils::toString(player.cipher.bx, n);
  string outputCom = StringUtils::toString(player.Ccom[0],n)+StringUtils::toString(player.Ccom[1],n)+StringUtils::toString(player.Ccom[2],n)+StringUtils::toString(player.Ccom[3],n);
  string* res = new string[2];
  res[0] = sha256(input+inputCom+output+outputCom);
  res[1] = output + outputCom;
  return res;
}

void fillContainerY(ZZ** CY[3], ZZ** r_com1, ZZ** C_com1, Ciphertext cipher1, ZZ** r_com2, ZZ** C_com2, Ciphertext cipher2, ZZ** r_com3, ZZ** C_com3, Ciphertext cipher3) {
  ZZ* Y1[6] = {cipher1.ax, cipher1.bx, C_com1[0], C_com1[1], C_com1[2], C_com1[3]};
  ZZ* Y2[6] = {cipher2.ax, cipher2.bx, C_com2[0], C_com2[1], C_com2[2], C_com2[3]};
  ZZ* Y3[6] = {cipher3.ax, cipher3.bx, C_com3[0], C_com3[1], C_com3[2], C_com3[3]};
  CY[0] = Y1;
  CY[1] = Y2;
  CY[2] = Y3;
}

string fillContainerA(string* Cont1, string* Cont2, string* Cont3) {
  string Y = Cont1[1] + Cont2[1] + Cont3[1];
  string Cs = Cont1[0] + Cont2[0] + Cont3[0];
  return Y + Cs;
}

void setCcom(ZZ** C_com, ZZ** Y) {
  C_com[0] = Y[2];
  C_com[1] = Y[3];
  C_com[2] = Y[4];
  C_com[3] = Y[5];
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////
int main() {
  // Parameters //
  long logq = 60; ///< Ciphertext modulus (this value should be <= logQ in "scr/Params.h")
  long logp = 23; ///< Scaling Factor (larger logp will give you more accurate value)
  long logn = 10; ///< number of slot is 1024 (this value should be < logN in "src/Params.h")
  long n = 1 << logn; /// n = slots
  long numThread = 8;
  long np = ceil((1 + logQQ + logN + 2)/59.0);

  // Construct and Generate Public Keys //
  srand(time(NULL));
  SetNumThreads(numThread);
  TimeUtils timeutils;
  Ring ring;
  SecretKey secretKey(ring);
  Scheme scheme(secretKey, ring);
  Key* key = scheme.keyMap.at(ENCRYPTION);
  scheme.addLeftRotKeys(secretKey); ///< When you need left rotation for the vectorized message
  scheme.addRightRotKeys(secretKey); ///< When you need right rotation for the vectorized message

  // Define a second ring for the BDOP commitments
  Ring ring2;
  SecretKey secretKey2(ring2);
  Scheme scheme2(secretKey2, ring2);
  scheme2.addLeftRotKeys(secretKey2); ///< When you need left rotation for the vectorized message
  scheme2.addRightRotKeys(secretKey2); ///< When you need right rotation for the vectorized message

////////////////////////////////////////////////////////////////// * Basic Parameters are in src/Params.h
/* BUILD A CIRCUIT */                                           // * If you want to use another parameter, you need to change src/Params.h file and re-complie this library.
////////////////////////////////////////////////////////////////// *
timeutils.start(ZKGEN, 0);
  // generate random tapes // deterministic for testing
  int k0 = 5;  // seeding for debugging
  int k1 = 12;
  int k2 = 23;
  int k3 = 30; 

  Player player0;
  ZZ* A_com[5] = {new ZZ[N], new ZZ[N], new ZZ[N], new ZZ[N], new ZZ[N]};
  player0.MX[0] = player0.VX;
  player0.MX[1] = player0.M0;
  player0.MX[2] = player0.M1;

// Generate secret 
  player0.mvec = EvaluatorUtils::randomComplexArray(n);

// Generate noises
  ring.sampleZO(player0.VX); // VX 
  ring.sampleGauss(player0.M0);
  ring.sampleGauss(player0.M1);
  genMatricesVec(player0.Rcom, A_com, ring, np, QQ);

  encryptInput2(scheme, ring, ring2, logp, logq, n, np, key, A_com, player0, QQ);
  ZZ qQ0 = ring.qpows[player0.plain.logq + logQ];
double tgen = timeutils.stop(ZKGEN, 0);

/// SIGN 
timeutils.start(ZKSPLIT, 0);
    Player player1;
    Player player2;
    Player player3;

  const unsigned char data1 = (unsigned char)k1;
  const unsigned char data2 = (unsigned char)k2;  

  // Make Random Array of Complex  X = X1 + X2 + X3
  srand(k1);
  player1.mvec = EvaluatorUtils::randomComplexArray(n);//new complex<double>[n];//
  srand(k2);
  player2.mvec = EvaluatorUtils::randomComplexArray(n);
  player3.mvec = new complex<double>[n];
  for (int k=0;k<n;k++){
    player3.mvec[k] = player0.mvec[k] - player1.mvec[k] - player2.mvec[k];
  }

// Create views for noise 
  SetSeed(&data1, 4);  
  noisedView(ring, player1.VX, player1.M0, player1.M1, player1.MX, player1.Rcom);
  SetSeed(&data2, 4);  
  noisedView(ring, player2.VX, player2.M0, player2.M1, player2.MX, player2.Rcom);
  splitNoises(ring, qQ0, player0.VX, player0.M0, player0.M1, player0.MX, player0.Rcom, player0.Ccom, player1.VX, player1.M0, player1.M1, player1.MX, player1.Rcom, player1.Ccom, player2.VX, player2.M0, player2.M1, player2.MX, player2.Rcom, player2.Ccom, player3.VX, player3.M0, player3.M1, player3.MX, player3.Rcom, player3.Ccom);
//  Encrypt Complex Input X1
  encryptInput(scheme, ring, ring2, player1.plain, player1.cipher, logp, logq, n, np, key, player1.mvec, A_com, player1.MX, player1.Rcom, player1.Ccom, player1.VX, player1.M0, player1.M1, QQ);
  //encryptInput2(scheme, ring, ring2, logp, logq, n, np, key, A_com, player1, QQ);

  encryptInput(scheme, ring, ring2, player2.plain, player2.cipher, logp, logq, n, np, key, player2.mvec, A_com, player2.MX, player2.Rcom, player2.Ccom, player2.VX, player2.M0, player2.M1, QQ);
  //encryptInput2(scheme, ring, ring2, logp, logq, n, np, key, A_com, player2, QQ);

  encryptInput(scheme, ring, ring2, player3.plain, player3.cipher, logp, logq, n, np, key, player3.mvec, A_com, player3.MX, player3.Rcom, player3.Ccom, player3.VX, player3.M0, player3.M1, QQ);
  //encryptInput2(scheme, ring, ring2, logp, logq, n, np, key, A_com, player3, QQ);

double tsplit = timeutils.stop(ZKSPLIT, 0);

timeutils.start(ZKSIGN, 0);
  //C1 = H(k1, x1, y1);  //C2 = H(k2, x2, y2); //C3 = H(k3, x3, y3);
  string* Cont1 = fillContainerC(k1, player1.mvec, player1.VX, player1.M0, player1.M1, player1.Rcom, player1.Ccom, player1.cipher, n);
  string* Cont2 = fillContainerC(k2, player2.mvec, player2.VX, player2.M0, player2.M1, player2.Rcom, player2.Ccom, player2.cipher, n);
  string* Cont3 = fillContainerC(k3, player3.mvec, player3.VX, player3.M0, player3.M1, player3.Rcom, player3.Ccom, player3.cipher, n);
  string CC[3] = {Cont1[0], Cont2[0], Cont3[0]};
  
  ZZ* Y1[6] = {player1.cipher.ax, player1.cipher.bx, player1.Ccom[0], player1.Ccom[1], player1.Ccom[2], player1.Ccom[3]};
  ZZ* Y2[6] = {player2.cipher.ax, player2.cipher.bx, player2.Ccom[0], player2.Ccom[1], player2.Ccom[2], player2.Ccom[3]};
  ZZ* Y3[6] = {player3.cipher.ax, player3.cipher.bx, player3.Ccom[0], player3.Ccom[1], player3.Ccom[2], player3.Ccom[3]};
  ZZ** CY[3] ={Y1, Y2, Y3};
  //ZZ** CY[3];
  //fillContainerY(CY, r_com1, C_com1, cipher1, r_com2, C_com2, cipher2, r_com3, C_com3, cipher3);

  string A = fillContainerA(Cont1, Cont2, Cont3);

/// Generate the proof 
  /// e <- H(a1, .., ai)
  string e = sha256(A);

  // interpret hash into 1, 2 or 3  
  int int_e = 0;
  for (const char s: e) {
    int_e += std::atoi(&s);
  }
  int_e %= 3;

  /// bi = ( ye+2,i, Ce+2,i)
  B CB;
  CB.y_e2_ = CY[(int_e+2)%3];
  CB.H_k_View_ = CC[(int_e+2)%3];

  /// Create z_i depending on challenge
  Z zs;
  if(int_e == 0) {
    zs.y_i_ = CY[1];
    zs.kz_1_ = k1;
    zs.kz_2_ = k2;
  }
  else if(int_e == 1) {
    zs.y_i_ = CY[2];
    zs.kz_1_ = k2;
    zs.kz_2_ = k3;
    zs.mvec_ = player3.mvec;
    zs.vx_ = player3.VX;
    zs.m0_ = player3.M0;
    zs.m1_ = player3.M1;
    zs.rv_ = player3.Rcom;
  }
  else {
    zs.y_i_ = CY[0];
    zs.kz_1_ = k3;
    zs.kz_2_ = k1;
    zs.mvec_ = player3.mvec;
    zs.vx_ = player3.VX;
    zs.m0_ = player3.M0;
    zs.m1_ = player3.M1;
    zs.rv_ = player3.Rcom;
  }

  /// p <- [e, (bi, zi), .. , (bt, zt)]
  Proof p;
  p.num_iterations_ = 1;
  p.e_ = int_e;
  p.y_e2_ = CY[int_e];
  p.H_k_View_ = CC[int_e];
  p.zs_ = zs;  
double tsig = timeutils.stop(ZKSIGN, 0);
///////////////////////////////////////////////////////////////////////////////////////////////
  // VERIFY the commitment
timeutils.start(ZKVER, 0);
  int e_v = p.e_;
  int k1_v = p.zs_.kz_1_;
  int k2_v = p.zs_.kz_2_;

  // init variables
  complex<double>* mvec_e_v;
  ZZ* vx_e_v = new ZZ[N];
  ZZ* m0_e_v = new ZZ[N];
  ZZ* m1_e_v = new ZZ[N];
  ZZ* r_com_e_v[3] = {new ZZ[N], new ZZ[N], new ZZ[N]};
  ZZ* mx_e_v[3] = {new ZZ[N], new ZZ[N], new ZZ[N]};

  complex<double>* mvec_e1_v;
  ZZ* vx_e1_v = new ZZ[N];
  ZZ* m0_e1_v = new ZZ[N];
  ZZ* m1_e1_v = new ZZ[N];
  ZZ* r_com_e1_v[3] = {new ZZ[N], new ZZ[N], new ZZ[N]};
  ZZ* mx_e1_v[3]= {new ZZ[N], new ZZ[N], new ZZ[N]};

  if(e_v == 0) {
    srand(k1_v);
    mvec_e_v = EvaluatorUtils::randomComplexArray(n);
    srand(k2_v);
    mvec_e1_v = EvaluatorUtils::randomComplexArray(n);
// Seed is artificially retrived from k1_v resp. k2_v. We reuse the memspace allocated prior.
    SetSeed(&data1, 4);
    noisedView(ring, vx_e_v, m0_e_v, m1_e_v, mx_e_v, r_com_e_v);

    SetSeed(&data2, 4);  
    noisedView(ring, vx_e1_v, m0_e1_v, m1_e1_v, mx_e1_v, r_com_e1_v);
  }
  else if(e_v == 1) {
    srand(k1_v);
    mvec_e_v = EvaluatorUtils::randomComplexArray(n);

    mvec_e1_v = zs.mvec_;
    vx_e1_v = zs.vx_;
    m0_e1_v = zs.m0_;
    m1_e1_v = zs.m1_;
    r_com_e1_v[0] = zs.rv_[0];
    r_com_e1_v[1] = zs.rv_[1];
    r_com_e1_v[2] = zs.rv_[2];
    mx_e1_v[0] = vx_e1_v;
    mx_e1_v[1] = m0_e1_v;
    mx_e1_v[2] = m1_e1_v;

  // Seed is artificially retrived from k1_v resp. k2_v. We reuse the memspace allocated prior.
    SetSeed(&data2, 4); 
    noisedView(ring, vx_e_v, m0_e_v, m1_e_v, mx_e_v, r_com_e_v);
  }
  else {
    mvec_e_v = zs.mvec_;
    vx_e_v = zs.vx_;
    m0_e_v = zs.m0_;
    m1_e_v = zs.m1_;
    r_com_e_v[0] = zs.rv_[0];
    r_com_e_v[1] = zs.rv_[1];
    r_com_e_v[2] = zs.rv_[2];
    mx_e_v[0] = vx_e_v;
    mx_e_v[1] = m0_e_v;
    mx_e_v[2] = m1_e_v;

    srand(k2_v);
    mvec_e1_v = EvaluatorUtils::randomComplexArray(n);
  // Seed is artificially retrived from k1_v resp. k2_v. We reuse the memspace allocated prior.
    SetSeed(&data1, 4);
    noisedView(ring, vx_e1_v, m0_e1_v, m1_e1_v, mx_e1_v, r_com_e1_v);
  }

  /// Extract yei+1_ from zi 
  ZZ** Y_e1_v = zs.y_i_;

  /// Extract yei+2_ and Cei+2 from bi
  ZZ** Y_e2_v = CB.y_e2_;
  string C_e2_v = CB.H_k_View_;

  /// Compute yei = \PHI(xei_) = yei__ 
  Plaintext plain_e_v;
  Ciphertext cipher_e_v;
  ZZ* C_com_e_v[4] = {new ZZ[N], new ZZ[N], new ZZ[N], new ZZ[N]};

  scheme.encode(plain_e_v, mvec_e_v, n, logp, logq);
  encrypt(&cipher_e_v,&plain_e_v,ring,key,n,logp,logq,np,vx_e_v,m0_e_v,m1_e_v);
  commitVec(C_com_e_v, mx_e_v, r_com_e_v, A_com, ring2, np, QQ);

  ZZ* Y_e_v[6] = {cipher_e_v.ax, cipher_e_v.bx, C_com_e_v[0], C_com_e_v[1], C_com_e_v[2], C_com_e_v[3]}; 

  /// Set yei+1__= yei+1_ // cf Y_e1_v about 20 lines above
  ZZ* C_com_e1_v[4] = {new ZZ[N], new ZZ[N], new ZZ[N], new ZZ[N]};
  setCcom(C_com_e1_v,Y_e1_v);

  ZZ* C_com_e2_v[4] = {new ZZ[N], new ZZ[N], new ZZ[N], new ZZ[N]};
  setCcom(C_com_e2_v,Y_e2_v);
  /// Compute yei+2__ = y + yei+1__ + yei__ // not really necessary as a primer

  /// Compute Ci and Di 
  string A_v; 
  string Y_v; 
  string Cs_v;

  string* Cont_e_v = fillContainerC(k1_v, mvec_e_v, vx_e_v, m0_e_v, m1_e_v, r_com_e_v, C_com_e_v, cipher_e_v, n);
  string C_e_v = Cont_e_v[0];

  string input_e1_v = std::to_string(k2_v)+StringUtils::toString(mvec_e1_v, n)+StringUtils::toString(vx_e1_v, n)+StringUtils::toString(m0_e1_v, n)+StringUtils::toString(m1_e1_v, n);
  string inputCom_e1_v = comToString(r_com_e1_v, n);
  string output_e1_v = StringUtils::toString(Y_e1_v[0], n)+StringUtils::toString(Y_e1_v[1], n);
  string outputCom_e1_v = StringUtils::toString(C_com_e1_v[0],n)+StringUtils::toString(C_com_e1_v[1],n)+StringUtils::toString(C_com_e1_v[2],n)+StringUtils::toString(C_com_e1_v[3],n);//comAllToString(Cv_e1_v, Cm0_e1_v, Cm1_e1_v, n, 2);
  string C_e1_v = sha256(input_e1_v + inputCom_e1_v + output_e1_v + outputCom_e1_v); 

  string output_e2_v = StringUtils::toString(Y_e2_v[0], n)+StringUtils::toString(Y_e2_v[1], n);
  string outputCom_e2_v = StringUtils::toString(C_com_e2_v[0],n)+StringUtils::toString(C_com_e2_v[1],n)+StringUtils::toString(C_com_e2_v[2],n)+StringUtils::toString(C_com_e2_v[3],n);//comAllToString(Cv_e2_v, Cm0_e2_v, Cm1_e2_v, n, 2);

  if(e_v == 0) {
    Y_v = Cont_e_v[1] + output_e1_v + outputCom_e1_v + output_e2_v + outputCom_e2_v;
    Cs_v =  C_e_v + C_e1_v + C_e2_v;
    A_v = Y_v + Cs_v;  

  } else if(e_v == 1) {
    Y_v = output_e2_v + outputCom_e2_v + Cont_e_v[1] + output_e1_v + outputCom_e1_v;
    Cs_v =  C_e2_v + C_e_v + C_e1_v;
    A_v = Y_v + Cs_v; 

  } else {
    Y_v = output_e1_v + outputCom_e1_v + output_e2_v + outputCom_e2_v + Cont_e_v[1];
    Cs_v =  C_e1_v + C_e2_v + C_e_v;
    A_v = Y_v + Cs_v; 
  }
  
/// Di = kj || yj__  
double tver = timeutils.stop(ZKVER, 0);

/// Compute challenge e = Hash(a1,.. at)  
string e_v_loc = sha256(A_v);
if (e == e_v_loc) {
  cout << "challenging player "<< e_v << " -- ";
  cout << "SUCCESS" <<endl;
  ofstream file("timings.csv", ios::app);
  file << e_v <<","<< tgen <<","<< tsplit <<","<< tsig <<","<< tver <<","<< "SUCCESS"<<"\n";
  file.close();

} else {
  cout << "ERROR" <<endl; 
  cout << e_v << endl;
  cout << e << endl;
  cout << e_v_loc << endl;
}
cout<<"fin de service"<<endl;

return 0;
}