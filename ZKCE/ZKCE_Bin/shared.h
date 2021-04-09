 /*
 ============================================================================
 Name        : shared.h
 Author      : ANONYMOUS - based on Sobuno's ZKBoo v0.1
 Version     : 1.0
 Description : Common functions for the BITDEC prover and verifier
 ============================================================================
 */

#ifndef SHARED_H_
#define SHARED_H_
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include "omp.h"

#define VERBOSE

static const uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

#define ySize 928 // value of *countY after the commit phase;

typedef struct {
	unsigned char x[64];
	uint32_t y[ySize];
} View;

typedef struct {
	uint32_t yp[3][32];
	unsigned char h[3][32];
} a;

typedef struct {
	uint32_t y[32];
	unsigned char h[32];
} b;

typedef struct {
	unsigned char ke[16];
	unsigned char ke1[16];
	View ve;
	View ve1;
	unsigned char re[4];
	unsigned char re1[4];
} z;

typedef struct {
	View ve1;
	int ke1;
	int ke;
	unsigned char x[64];
} zz;


#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))


void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}


EVP_CIPHER_CTX* setupAES(unsigned char key[16]) {
	EVP_CIPHER_CTX *ctx;

	#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	ctx = EVP_CIPHER_CTX_new();
	#else
	ctx = malloc(sizeof(*ctx));
	#endif
	if (!ctx) {
		fprintf(stderr, "Out of memory: EVP_CIPHER_CTX!\n");
		return ctx; // from -1 to ctx to keep consistency in the returned data type
	}
	EVP_CIPHER_CTX_init(ctx);

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"01234567890123456";

	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();

	return ctx;


}

uint32_t bits2int(unsigned char* input) {
	uint32_t out = 0;
	for(int j=0; j<32; j++) {
		out += ((uint32_t)input[32 - j -1]) << j;
	}
	return out;
}


void getAllRandomness(unsigned char key[16], unsigned char randomness[3552]) {
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations
	EVP_CIPHER_CTX *ctx;
	ctx = setupAES(key);
	unsigned char *plaintext =
			(unsigned char *)"0000000000000000";
	int len;
	for(int j=0;j<182;j++) {
		if(1 != EVP_EncryptUpdate(ctx, &randomness[j*16], &len, plaintext, strlen ((char *)plaintext)))
			handleErrors();

	}
	EVP_CIPHER_CTX_cleanup(ctx);
}

uint32_t getRandom32(unsigned char randomness[3552], int randCount) {
	uint32_t ret;
	memcpy(&ret, &randomness[randCount], 4);
	return ret;
}

uint32_t getRandom1(unsigned char randomness[3552], int randCount) {
	uint32_t ret;
	memcpy(&ret, &randomness[randCount], 1);
	return (ret >> 1) & 1;
}

void init_EVP() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	//OPENSSL_config(NULL);
}

void cleanup_EVP() {
	EVP_cleanup();
	ERR_free_strings();
}

void print_hash(unsigned char digest[SHA256_DIGEST_LENGTH]) {
	for(int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
        printf("%02x", digest[j]);
	}
	putchar( '\n' );
}

void H(unsigned char k[16], View v, unsigned char r[4], unsigned char hash[SHA256_DIGEST_LENGTH]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, k, 16);
	SHA256_Update(&ctx, &v, sizeof(v));
	SHA256_Update(&ctx, r, 4);
	SHA256_Final(hash, &ctx);
}


void H3(uint32_t y[8], a* as, int s, int* es) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, y, 32);
	SHA256_Update(&ctx, as, sizeof(a)*s);
	SHA256_Final(hash, &ctx);

	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < s) {
		if(bitTracker >= SHA256_DIGEST_LENGTH*8) { //Generate new hash as we have run out of bits in the previous hash
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, sizeof(hash));
			SHA256_Final(hash, &ctx);
			bitTracker = 0;
		}

		int b1 = GETBIT(hash[bitTracker/8], bitTracker % 8);
		int b2 = GETBIT(hash[(bitTracker+1)/8], (bitTracker+1) % 8);
		if(b1 == 0) {
			if(b2 == 0) {
				es[i] = 0;
				bitTracker += 2;
				i++;
			} else {
				es[i] = 1;
				bitTracker += 2;
				i++;
			}
		} else {
			if(b2 == 0) {
				es[i] = 2;
				bitTracker += 2;
				i++;
			} else {
				bitTracker += 2;
			}
		}
	}

}

void output(View v, uint32_t* result) {
	memcpy(result, &v.y[ySize-32], 32);
}

void outputSHA(View v, uint32_t* result) {
	memcpy(result, &v.y[ySize-8], 32);
}

void reconstruct(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* result) {
	for (int i = 0; i < 32; i++) {
		result[i] = y0[i] ^ y1[i] ^ y2[i];
	}
}

void reconstructSHA(uint32_t* y0, uint32_t* y1, uint32_t* y2, uint32_t* result) {
	for (int i = 0; i < 8; i++) {
		result[i] = y0[i] ^ y1[i] ^ y2[i];
	}
}

void mpc_XOR2(uint32_t x[2], uint32_t y[2], uint32_t z[2]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
}

void mpc_NEGATE2(uint32_t x[2], uint32_t z[2]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
}

omp_lock_t *locks;

void openmp_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
  {
    omp_set_lock(&locks[type]);
  }
  else
  {
    omp_unset_lock(&locks[type]);
  }
}


unsigned long openmp_thread_id(void)
{
  return (unsigned long)omp_get_thread_num();
}

void openmp_thread_setup(void)
{
  int i;

  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (i=0; i<CRYPTO_num_locks(); i++)
  {
    omp_init_lock(&locks[i]);
  }

  CRYPTO_set_id_callback((unsigned long (*)())openmp_thread_id);
  CRYPTO_set_locking_callback((void (*)())openmp_locking_callback);
}

void openmp_thread_cleanup(void)
{
  int i;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    omp_destroy_lock(&locks[i]);
  OPENSSL_free(locks);
}


int mpc_AND_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom1(randomness[0], *randCount), getRandom1(randomness[1], *randCount) };
	*randCount += 1;

	uint32_t t = 0;

	t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	z[0] = t;
	ve->y[*countY] = z[0];
	z[1] = ve1->y[*countY];
	

	(*countY)++;
	return 0;
}

int mpc_ADD_verify(uint32_t x[2], uint32_t y[2], uint32_t z[2], View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount, int* countY) {
	uint32_t c[2] = { 0 };
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint8_t a[2], b[2];

	uint8_t t;

	for(int i=0;i<31;i++) {
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^(ve1->y[*countY]),i);
 
		b[0]=GETBIT(y[0]^c[0],i);
		b[1]=GETBIT(y[1]^(ve1->y[*countY]),i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);

		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

	}

	z[0]=x[0]^y[0]^c[0];

	ve->y[*countY] = c[0];

	z[1]=x[1]^y[1]^ve1->y[*countY];
	(*countY)++;
	return 0;
}


int mpc_GAMMA_verify(uint32_t x1[2], uint32_t x2[2], uint32_t x3[2], uint32_t z[2], View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom1(randomness[0], *randCount), getRandom1(randomness[1], *randCount)};
	*randCount += 1;
	uint32_t t[2] = { 0 };
	uint32_t AC[2] = { 0 };
	uint32_t BC[2] = { 0 };

	AC[0] = x1[0] ^ x3[0] ^ 1;
	AC[1] = x1[1] ^ x3[1] ^ 1;

	BC[0] = x2[0] ^ x3[0];
	BC[1] = x2[1] ^ x3[1];

	mpc_AND_verify(AC,BC,t,ve, ve1,randomness,randCount,countY);

	z[0] = t[0] ^ x2[0];
	ve->y[*countY] = z[0];
	z[1] = t[1] ^ x2[1];

	(*countY)++;
}

void mpc_gateA_verify(uint32_t x[2], uint32_t z[2], int e, View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount,  int* countY) {
	uint32_t r[2] = { getRandom1(randomness[0], *randCount), getRandom1(randomness[1], *randCount)};
	*randCount += 1;
	uint32_t t = 0;

	if (e == 0) {
		t = 0 ^ r[0] ^ r[1];
	} else if (e == 1) {
		t = x[0] ^ x[1] ^ r[0] ^ r[1];
	} else {
		t = 0 ^ r[0] ^ r[1];
	}  

	z[0] = t;
	ve->y[*countY] = z[0];
	z[1] = ve1->y[*countY];

	(*countY)++;
}

void mpc_gateB_verify(uint32_t x[2], uint32_t z[2], int e, View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount,  int* countY) {
	uint32_t r[2] = { getRandom1(randomness[0], *randCount), getRandom1(randomness[1], *randCount)};
	*randCount += 1;
	uint32_t t = 0;
	if (e == 0) {
		t = 0 ^ r[0] ^ r[1];
	} else if (e == 1) {
		t = 0 ^ r[0] ^ r[1];
	} else {
		t =  x[0] ^ x[1] ^ 1 ^ r[0] ^ r[1];
	}  
	z[0] = t;
	ve->y[*countY] = z[0];
	z[1] = ve1->y[*countY];
	(*countY)++;
}

int mpc_BETA_verify(uint32_t x[2], uint32_t z[2], int e, View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount, int* countY) {
	uint32_t r[2] = { getRandom1(randomness[0], *randCount), getRandom1(randomness[1], *randCount) };
	*randCount += 1;

	uint32_t a[2], b[2];

	uint32_t AC[2] = { 0 };
	uint32_t BC[2] = { 0 };

	uint32_t tmp[2];
	uint32_t t;

	mpc_gateA_verify(x, BC, e, ve, ve1, randomness, randCount, countY);

	mpc_gateB_verify(x, AC, e, ve, ve1, randomness, randCount, countY);

	mpc_AND_verify(AC,BC,tmp, ve, ve1, randomness,randCount,countY);

	if (e == 0) {
		t = tmp[0];
	} else if (e == 1) {
		t = tmp[0] ^ x[0];
	} else {
		t =  tmp[0];
	}

	z[0]=t;
	ve->y[*countY] = z[0];
	z[1]=ve1->y[*countY];

	(*countY)++;
	return 0;
}

void mpc_RIGHTROTATE2(uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
}

void mpc_RIGHTSHIFT2(uint32_t x[2], int i, uint32_t z[2]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
}


int mpc_MAJ_verify(uint32_t a[2], uint32_t b[2], uint32_t c[2], uint32_t z[3], View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount, int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR2(a, b, t0);
	mpc_XOR2(a, c, t1);
	if(mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(z, a, z);
	return 0;
}

int mpc_CH_verify(uint32_t e[2], uint32_t f[2], uint32_t g[2], uint32_t z[2], View* ve, View* ve1, unsigned char randomness[2][3552], int* randCount, int* countY) {

	uint32_t t0[3];
	mpc_XOR2(f,g,t0);
	if(mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR2(t0,g,z);


	return 0;
}

a verifyZ(uint32_t y[32], int e, b b, zz zz) {

	// Reconstruct input for ZKB++
	unsigned char rs[2][4];
	unsigned char keys[2][16];
	unsigned char shares[2][32];


	// Create local z container for verif
	z z;
	int ke = zz.ke;
	int ke1 = zz.ke1;

	//printf("ke  %u\n", ke);
	srand(ke);
	for(int k=0; k<16; k++){
		keys[0][k] = rand() % 256;
	}
	for(int k=0; k<4; k++){
		rs[0][k] = rand() % 256;
	}
	for(int k=0; k<32; k++){
		shares[0][k] = (rand() % 256)%2;
	}

	//printf("ke1 %u\n", ke1);
	srand(ke1);
	for(int k=0; k<16; k++){
		keys[1][k] = rand() % 256;
	}
	for(int k=0; k<4; k++){
		rs[1][k] = rand() % 256;
	}
	for(int k=0; k<32; k++){
		shares[1][k] = (rand() % 256)%2;
	}

	if(e==0){
		z.ve1 = zz.ve1;
		memcpy(z.ve.x, shares[0], 32);
		uint32_t inputAe = bits2int(z.ve.x);

		memcpy(z.ve1.x, shares[1], 32);
		
		memcpy(z.ke, keys[0], 16);
		memcpy(z.ke1, keys[1], 16);

	}else if(e==1){
		memcpy(z.ve.x, shares[0], 32);

		z.ve1 = zz.ve1;

		memcpy(z.ke, keys[0], 16);
		memcpy(z.ke1, keys[1], 16);
		memcpy(z.ve1.x, zz.x, 32);

		uint32_t inputAe1 = bits2int(z.ve1.x);

	}else{

		memcpy(z.ve1.x,  shares[1], 32);

		z.ve1 = zz.ve1;
		memcpy(z.ke, keys[0], 16);
		memcpy(z.ke1, keys[1], 16);
		memcpy(z.ve.x, zz.x, 32);

		uint32_t inputAe = bits2int(z.ve.x);

		uint32_t inputAe1 = bits2int(z.ve1.x);

	}

	unsigned char randomness[2][3552];
	getAllRandomness(z.ke, randomness[0]);
	getAllRandomness(z.ke1, randomness[1]);

	// recontsructed input and noise keys  shares, rs, keys OK nov 10th
	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));


//VERIFY BIT DECOMPOSITION
	uint32_t gamma_e_e1[2];
	gamma_e_e1[0] = 0;
	gamma_e_e1[1] = 0;

	uint32_t beta_e_e1[2];
	beta_e_e1[0] = 0;
	beta_e_e1[1] = 0;

	uint32_t res_e_e1[2][32];

	uint32_t Xe_e1[2];
	
	for (int j = 31; j>=0; j--) {
		Xe_e1[0] = z.ve.x[j];
		Xe_e1[1] = z.ve1.x[j];	

		// Compute alpha
		res_e_e1[0][j] = (Xe_e1[0] ^ gamma_e_e1[0] ^ beta_e_e1[0]);
		res_e_e1[1][j] = (Xe_e1[1] ^ gamma_e_e1[1] ^ beta_e_e1[1]);

		// Compute gamma
		uint32_t AC[2] = { 0 };
		uint32_t BC[2] = { 0 };

		AC[0] = Xe_e1[0] ^ gamma_e_e1[0] ^ 1;
		AC[1] = Xe_e1[1] ^ gamma_e_e1[1] ^ 1;

		BC[0] = beta_e_e1[0] ^ gamma_e_e1[0];
		BC[1] = beta_e_e1[1] ^ gamma_e_e1[1];

		mpc_AND_verify(AC,BC,gamma_e_e1,&z.ve, &z.ve1,randomness,randCount,countY);

		gamma_e_e1[0] = gamma_e_e1[0] ^ beta_e_e1[0];
		gamma_e_e1[1] = gamma_e_e1[1] ^ beta_e_e1[1];

		// Compute beta
		mpc_BETA_verify(Xe_e1, beta_e_e1, e, &z.ve, &z.ve1, randomness, randCount, countY);
	}

	// Explicitely add the output of the Bitdec to the views
	for (int j = 0; j < 32; ++j) {
		z.ve.y[*countY] = res_e_e1[0][j];
		(*countY)++;
	}

// CONVERSION FROM BITS TO BYTES

	unsigned char input_byte_e[4];
	unsigned char input_byte_e1[4];
for(int i=0;i<4;i++) {
		// Player 1
		SETBIT(input_byte_e[i], 7,   res_e_e1[0][i*8]);
		SETBIT(input_byte_e[i], 6, res_e_e1[0][i*8+1]);
		SETBIT(input_byte_e[i], 5, res_e_e1[0][i*8+2]);
		SETBIT(input_byte_e[i], 4, res_e_e1[0][i*8+3]);
		SETBIT(input_byte_e[i], 3, res_e_e1[0][i*8+4]);
		SETBIT(input_byte_e[i], 2, res_e_e1[0][i*8+5]);
		SETBIT(input_byte_e[i], 1, res_e_e1[0][i*8+6]);
		SETBIT(input_byte_e[i], 0, res_e_e1[0][i*8+7]);

		// Player 2
		SETBIT(input_byte_e1[i], 7,   res_e_e1[1][i*8]);
		SETBIT(input_byte_e1[i], 6, res_e_e1[1][i*8+1]);
		SETBIT(input_byte_e1[i], 5, res_e_e1[1][i*8+2]);
		SETBIT(input_byte_e1[i], 4, res_e_e1[1][i*8+3]);
		SETBIT(input_byte_e1[i], 3, res_e_e1[1][i*8+4]);
		SETBIT(input_byte_e1[i], 2, res_e_e1[1][i*8+5]);
		SETBIT(input_byte_e1[i], 1, res_e_e1[1][i*8+6]);
		SETBIT(input_byte_e1[i], 0, res_e_e1[1][i*8+7]);
	}

// VERIFY SHA256
	unsigned char* mpcHASHinput_e_e1[2];
	mpcHASHinput_e_e1[0] = input_byte_e;
	mpcHASHinput_e_e1[1] = input_byte_e1;

	int numBits = 32; 
	uint32_t w[64][2];
	int chars = numBits >> 3;
	unsigned char* chunks[2];

	chunks[0] = calloc(64, 1);
	memcpy(chunks[0], input_byte_e, chars);
	chunks[0][chars] = 0x80;
	chunks[0][62] = numBits >> 8;
	chunks[0][63] = numBits;

	chunks[1] = calloc(64, 1);
	memcpy(chunks[1], input_byte_e1, chars);
	chunks[1][chars] = 0x80;
	chunks[1][62] = numBits >> 8;
	chunks[1][63] = numBits;

	for (int j = 0; j < 16; j++) {
		w[j][0] = (chunks[0][j * 4] << 24) | (chunks[0][j * 4 + 1] << 16) | (chunks[0][j * 4 + 2] << 8) | chunks[0][j * 4 + 3];
		w[j][1] = (chunks[1][j * 4] << 24) | (chunks[1][j * 4 + 1] << 16) | (chunks[1][j * 4 + 2] << 8) | chunks[1][j * 4 + 3];
	}


	uint32_t s0[2], s1[2];
	uint32_t t0[2], t1[2];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE2(w[j-15], 7, t0);
		mpc_RIGHTROTATE2(w[j-15], 18, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTSHIFT2(w[j-15], 3, t1);
		mpc_XOR2(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE2(w[j-2], 17, t0);
		mpc_RIGHTROTATE2(w[j-2], 19, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTSHIFT2(w[j-2],10,t1);
		mpc_XOR2(t0, t1, s1);


		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];
		mpc_ADD_verify(w[j-16], s0, t1, &z.ve, &z.ve1, randomness, randCount, countY);
		mpc_ADD_verify(w[j-7], t1, t1, &z.ve, &z.ve1, randomness, randCount, countY);
		mpc_ADD_verify(t1, s1, w[j], &z.ve, &z.ve1, randomness, randCount, countY);

	}

	uint32_t va[2] = { hA[0],hA[0] };
	uint32_t vb[2] = { hA[1],hA[1] };
	uint32_t vc[2] = { hA[2],hA[2] };
	uint32_t vd[2] = { hA[3],hA[3] };
	uint32_t ve[2] = { hA[4],hA[4] };
	uint32_t vf[2] = { hA[5],hA[5] };
	uint32_t vg[2] = { hA[6],hA[6] };
	uint32_t vh[2] = { hA[7],hA[7] };
	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE2(ve, 6, t0);
		mpc_RIGHTROTATE2(ve, 11, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(ve, 25, t1);
		mpc_XOR2(t0, t1, s1);

		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];
		//t0 = h + s1
		mpc_ADD_verify(vh, s1, t0, &z.ve, &z.ve1, randomness, randCount, countY);
		mpc_CH_verify(ve, vf, vg, t1, &z.ve, &z.ve1, randomness, randCount, countY);

		//t1 = t0 + t1 (h+s1+ch)
		mpc_ADD_verify(t0, t1, t1, &z.ve, &z.ve1, randomness, randCount, countY);

		t0[0] = k[i];
		t0[1] = k[i];
		mpc_ADD_verify(t1, t0, t1, &z.ve, &z.ve1, randomness, randCount, countY);
		mpc_ADD_verify(t1, w[i], temp1, &z.ve, &z.ve1, randomness, randCount, countY);

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE2(va, 2, t0);
		mpc_RIGHTROTATE2(va, 13, t1);
		mpc_XOR2(t0, t1, t0);
		mpc_RIGHTROTATE2(va, 22, t1);
		mpc_XOR2(t0, t1, s0);

		//maj = (a & (b ^ c)) ^ (b & c);
		//(a & b) ^ (a & c) ^ (b & c)
		mpc_MAJ_verify(va, vb, vc, maj, &z.ve, &z.ve1, randomness, randCount, countY);

		//temp2 = s0+maj;
		mpc_ADD_verify(s0, maj, temp2, &z.ve, &z.ve1, randomness, randCount, countY);

		memcpy(vh, vg, sizeof(uint32_t) * 2);
		memcpy(vg, vf, sizeof(uint32_t) * 2);
		memcpy(vf, ve, sizeof(uint32_t) * 2);
		//e = d+temp1;
		mpc_ADD_verify(vd, temp1, ve, &z.ve, &z.ve1, randomness, randCount, countY);

		memcpy(vd, vc, sizeof(uint32_t) * 2);
		memcpy(vc, vb, sizeof(uint32_t) * 2);
		memcpy(vb, va, sizeof(uint32_t) * 2);
		//a = temp1+temp2;

		mpc_ADD_verify(temp1, temp2, va, &z.ve, &z.ve1, randomness, randCount, countY);
	}

	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
	mpc_ADD_verify(hHa[0], va, hHa[0], &z.ve, &z.ve1, randomness, randCount, countY);
	mpc_ADD_verify(hHa[1], vb, hHa[1], &z.ve, &z.ve1, randomness, randCount, countY);
	mpc_ADD_verify(hHa[2], vc, hHa[2], &z.ve, &z.ve1, randomness, randCount, countY);
	mpc_ADD_verify(hHa[3], vd, hHa[3], &z.ve, &z.ve1, randomness, randCount, countY);
	mpc_ADD_verify(hHa[4], ve, hHa[4], &z.ve, &z.ve1, randomness, randCount, countY);
	mpc_ADD_verify(hHa[5], vf, hHa[5], &z.ve, &z.ve1, randomness, randCount, countY);
	mpc_ADD_verify(hHa[6], vg, hHa[6], &z.ve, &z.ve1, randomness, randCount, countY);
	mpc_ADD_verify(hHa[7], vh, hHa[7], &z.ve, &z.ve1, randomness, randCount, countY);

	unsigned char* results[2];
	results[0] = malloc(32);
	results[1] = malloc(32);
	uint32_t tmp0[2], tmp1[2], tmp2[2];
	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT2(hHa[i], 24, tmp0);
		results[0][i * 4] = tmp0[0];
		results[1][i * 4] = tmp0[1];
		mpc_RIGHTSHIFT2(hHa[i], 16, tmp1);
		results[0][i * 4 + 1] = tmp1[0];
		results[1][i * 4 + 1] = tmp1[1];
		mpc_RIGHTSHIFT2(hHa[i], 8, tmp2);
		results[0][i * 4 + 2] = tmp2[0];
		results[1][i * 4 + 2] = tmp2[1];
		results[0][i * 4 + 3] = hHa[i][0];
		results[1][i * 4 + 3] = hHa[i][1];
	}


	for(int i = 0; i<8; i++) {
		z.ve.y[*countY] = (results[0][i * 4] << 24) | (results[0][i * 4 + 1] << 16) | (results[0][i * 4 + 2] << 8) | results[0][i * 4 + 3];
		*countY += 1;
	}

	uint32_t* result_e = malloc(32);
	outputSHA(z.ve, result_e);

	uint32_t* result_e1 = malloc(32);
	outputSHA(zz.ve1, result_e1);


	// Check the correctness of the output ye2 = y ^ ye ^ ye1
	uint32_t y_rec[8];
	reconstructSHA(result_e,result_e1,b.y,y_rec);

	// Construct the containers
	a a_res;
	memcpy(a_res.yp[e], result_e, 32);
	memcpy(a_res.yp[(e+1)%3], result_e1, 32);
	memcpy(a_res.yp[(e+2)%3], b.y, 32);

	unsigned char hash1[SHA256_DIGEST_LENGTH];
	H(keys[0], z.ve, rs[0], hash1);
	memcpy(a_res.h[e], &hash1, 32);

	H(keys[1], zz.ve1, rs[1], hash1);
	memcpy(a_res.h[(e+1)%3], &hash1, 32);

	memcpy(a_res.h[(e+2)%3], b.h, 32);


	#ifdef VERBOSE
	printf("SUCCESS challenge - %u\n", e);
	#endif
	free(randCount);
	free(countY);

	return a_res;
}


#endif /* SHARED_H_ */

