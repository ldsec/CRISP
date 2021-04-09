package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"
	"github.com/ldsec/lattigo/ckks"
)

func randomFloat(min, max float64) float64 {
	return min + rand.Float64()*(max-min)
}


func mainfunk() {
	rand.Seed(time.Now().UnixNano())

	// Scheme params
	params := ckks.DefaultParams[13]

	// Context
	var ckkscontext *ckks.CkksContext
	ckkscontext = ckks.NewCkksContext(params)

	encoder := ckkscontext.NewEncoder()

	// Keys
	kgen := ckkscontext.NewKeyGenerator()
	var sk *ckks.SecretKey
	var pk *ckks.PublicKey
	sk, pk = kgen.NewKeyPair()

	// Relinearization key
	//var rlk *ckks.EvaluationKey
	//rlk = kgen.NewRelinKey(sk)

	// Rotation key
	rotkeys := ckkscontext.NewRotationKeys()
	for i:=uint64(1); i <= ckkscontext.Slots()>>1; i <<= 1 {
		kgen.GenRot(ckks.RotationLeft, sk, i, rotkeys) 
	}

	// Encryptor
	var encryptor *ckks.Encryptor
	encryptor = ckkscontext.NewEncryptorFromPk(pk)

	// Decryptor
	var decryptor *ckks.Decryptor
	decryptor = ckkscontext.NewDecryptor(sk)

	// Evaluator
	var evaluator *ckks.Evaluator
	evaluator = ckkscontext.NewEvaluator()

	// Values to encrypt
	values := make([]complex128, ckkscontext.Slots())
	var res float64 
	mask := make([]complex128, ckkscontext.Slots())
	for i := range values {
		values[i] = complex(randomFloat(0, 8), 0)
		res += real(values[i])
		mask[i] = complex(float64(3),0)
	}

	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())

	fmt.Println()
	fmt.Printf("Values     : %6f %6f %6f %6f...\n", values[0], values[1], values[2], values[3])
	fmt.Println()

	// Plaintext creation and encoding process
	plaintext := ckkscontext.NewPlaintext(ckkscontext.Levels()-1, ckkscontext.Scale())
	encoder.Encode(plaintext, values, ckkscontext.Slots())

	// Encryption process
	var ciphertext *ckks.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)

	// Adding
	//evaluator.Add(ciphertext,ciphertext,ciphertext)

	// Square
	//evaluator.MulRelin(ciphertext,ciphertext,rlk,ciphertext)
	//evaluator.Rescale(ciphertext,ckkscontext.Scale(),ciphertext)

	// Mask
	plaint_mask := ckkscontext.NewPlaintext(ciphertext.Level(), ciphertext.Scale())
	encoder.Encode(plaint_mask, mask, ckkscontext.Slots())
	evaluator.MulRelin(plaint_mask,ciphertext,nil,ciphertext)

	// Rotation
	//evaluator.RotateColumns(ciphertext,1,rotkeys,ciphertext)


	// Inner sum
	//cTmp := ckkscontext.NewCiphertext(1, ckkscontext.Levels()-1, ckkscontext.Scale())
	//for i := uint64(1); i <= ckkscontext.Slots()>>1; i <<= 1 {
	//	evaluator.RotateColumns(ciphertext, i, rotkeys, cTmp)
	//	evaluator.Add(cTmp, ciphertext, ciphertext.Ciphertext())
	//}

	// Decryption process + Decoding process
	valuesTest := encoder.Decode(decryptor.DecryptNew(ciphertext), ckkscontext.Slots())

	// Printing results and comparison
	fmt.Println()
	fmt.Printf("ValuesTest : %6f %6f %6f %6f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant : %6f %6f %6f %6f...\n", math.Pow(real(values[0]),2), math.Pow(real(values[1]),2), math.Pow(real(values[2]),2), math.Pow(real(values[3]),2))
	fmt.Printf("res : %6f\n", res)
}







/*func mainSM() {
	rand.Seed(time.Now().UnixNano())

	// Scheme params
	params := ckks.DefaultParams[13] // 46 23 10  -> 23 23 30

	// Context
	var ckkscontext *ckks.CkksContext
	ckkscontext = ckks.NewCkksContext(params)

	encoder := ckkscontext.NewEncoder()

	// Keys
	kgen := ckkscontext.NewKeyGenerator()
	var sk *ckks.SecretKey
	var pk *ckks.PublicKey
	sk, pk = kgen.NewKeyPair()

	// Relinearization key
	//var rlk *ckks.EvaluationKey
	//rlk = kgen.NewRelinKey(sk)

	// Rotation key 2
	//var evak1 *ckks.RotationKey
	//evak1 = kgen.NewRotationKey(1)

	// Encryptor
	var encryptor *ckks.Encryptor
	encryptor = ckkscontext.NewEncryptorFromPk(pk)

	// Decryptor
	var decryptor *ckks.Decryptor
	decryptor = ckkscontext.NewDecryptor(sk)

	// Evaluator
	var evaluator *ckks.Evaluator
	evaluator = ckkscontext.NewEvaluator()


	// Import values
	// Compute cleartext sum

	// Get number of ciphertexts


	// Values to encrypt
	values := make([]complex128, ckkscontext.Slots())
	mask := make([]complex128, ckkscontext.Slots())
	for i := range values {
		values[i] = complex(randomFloat(0, 8), 0)
		mask[i] = complex(float64(i),0)
	}

	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())

	fmt.Println()
	fmt.Printf("Values     : %6f %6f %6f %6f...\n", values[0], values[1], values[2], values[3])
	fmt.Println()

	// Plaintext creation and encoding process
	plaintext := ckkscontext.NewPlaintext(ckkscontext.Levels()-1, ckkscontext.Scale())
	encoder.Encode(plaintext, values, ckkscontext.Slots())

	// Encryption process FOR EACH CIPHERTEXT
	var ciphertext *ckks.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)

	// Adding to slot 0 for packed ct   // copy InnerSum from bfv evlauator 619
		// j=0..log2(n): leftRotateFast(2^j); addAndEqual

	// Adding to slot 0 for NOT packed ct
		// j=0..log2(nbr%(n+1)): leftRotateFast(2^j); addAndEqual

	// Add ciphertexts together

	// Decryption process + Decoding process
	valuesTest := encoder.Decode(decryptor.DecryptNew(ciphertext), ckkscontext.Slots())

	// Printing results and comparison
	fmt.Println()
	fmt.Printf("ValuesTest : %6f %6f %6f %6f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant : %6f %6f %6f %6f...\n", math.Pow(real(values[0]),2), math.Pow(real(values[1]),2), math.Pow(real(values[2]),2), math.Pow(real(values[3]),2))

}



func mainDS() {
	rand.Seed(time.Now().UnixNano())

	// Scheme params
	params := ckks.DefaultParams[13] // 60 25 10

	// Context
	var ckkscontext *ckks.CkksContext
	ckkscontext = ckks.NewCkksContext(params)

	encoder := ckkscontext.NewEncoder()

	// Keys
	kgen := ckkscontext.NewKeyGenerator()
	var sk *ckks.SecretKey
	var pk *ckks.PublicKey
	sk, pk = kgen.NewKeyPair()

	// Relinearization key
	//var rlk *ckks.EvaluationKey
	//rlk = kgen.NewRelinKey(sk)

	// Rotation key 2^j
	//var evak1 *ckks.RotationKey
	//evak1 = kgen.NewRotationKey(1)

	// Encryptor
	var encryptor *ckks.Encryptor
	encryptor = ckkscontext.NewEncryptorFromPk(pk)

	// Decryptor
	var decryptor *ckks.Decryptor
	decryptor = ckkscontext.NewDecryptor(sk)

	// Evaluator
	var evaluator *ckks.Evaluator
	evaluator = ckkscontext.NewEvaluator()


	// Get data from file
	// Get weights for disease
	// Compute cleartext DS
	// Create X

	// Values to encrypt
	values := make([]complex128, ckkscontext.Slots())
	mask := make([]complex128, ckkscontext.Slots())
	for i := range values {
		values[i] = complex(randomFloat(0, 8), 0)
		mask[i] = complex(float64(i),0)
	}

	// Create mask with weights

	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())

	fmt.Println()
	fmt.Printf("Values     : %6f %6f %6f %6f...\n", values[0], values[1], values[2], values[3])
	fmt.Println()

	// Plaintext creation and encoding process
	plaintext := ckkscontext.NewPlaintext(ckkscontext.Levels()-1, ckkscontext.Scale())
	encoder.Encode(plaintext, values, ckkscontext.Slots())

	// Encryption process
	var ciphertext *ckks.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)


	// Mask the vector
		// multiply by mask

	// Sum to slot 0
		// for j=0..log2(pts): leftRotateFast(ct; 2^j) ; add_and_equal

	// Decryption process + Decoding process
	valuesTest := encoder.Decode(decryptor.DecryptNew(ciphertext), ckkscontext.Slots())

	// Printing results and comparison
	fmt.Println()
	fmt.Printf("ValuesTest : %6f %6f %6f %6f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant : %6f %6f %6f %6f...\n", math.Pow(real(values[0]),2), math.Pow(real(values[1]),2), math.Pow(real(values[2]),2), math.Pow(real(values[3]),2))

}


func mainDist() {
	rand.Seed(time.Now().UnixNano())

	// Scheme params
	params := ckks.DefaultParams[13] // 200 23 12

	// Context
	var ckkscontext *ckks.CkksContext
	ckkscontext = ckks.NewCkksContext(params)

	encoder := ckkscontext.NewEncoder()

	// Keys
	kgen := ckkscontext.NewKeyGenerator()
	var sk *ckks.SecretKey
	var pk *ckks.PublicKey
	sk, pk = kgen.NewKeyPair()

	// Relinearization key
	//var rlk *ckks.EvaluationKey
	//rlk = kgen.NewRelinKey(sk)

	// Rotation key 1
	//var evak1 *ckks.RotationKey
	//evak1 = kgen.NewRotationKey(1)

	// Rotation key n/2
	//var evak1 *ckks.RotationKey
	//evak1 = kgen.NewRotationKey(1)

	// Rotation key 2^j
	//var evak1 *ckks.RotationKey
	//evak1 = kgen.NewRotationKey(1)

	// Encryptor
	var encryptor *ckks.Encryptor
	encryptor = ckkscontext.NewEncryptorFromPk(pk)

	// Decryptor
	var decryptor *ckks.Decryptor
	decryptor = ckkscontext.NewDecryptor(sk)

	// Evaluator
	var evaluator *ckks.Evaluator
	evaluator = ckkscontext.NewEvaluator()

	// Values to encrypt
	values := make([]complex128, ckkscontext.Slots())
	mask_in := make([]complex128, ckkscontext.Slots())
	mask_out := make([]complex128, ckkscontext.Slots())
	for i := range values {
		values[i] = complex(randomFloat(0, 8), 0)
		mask_in[i] = complex(float64(1/norm_i),0) // norm_i = (Vmax)*deltaT[i]/sqrt(8);
		mask_out[i] = complex(float64(1),0)
	}

	// Get real distance 
	// Get Vmax
	// Populate X

	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())

	fmt.Println()
	fmt.Printf("Values     : %6f %6f %6f %6f...\n", values[0], values[1], values[2], values[3])
	fmt.Println()

	// Plaintext creation and encoding process
	plaintext := ckkscontext.NewPlaintext(ckkscontext.Levels()-1, ckkscontext.Scale())
	encoder.Encode(plaintext, values, ckkscontext.Slots())

	// Encryption process
	var ciphertext *ckks.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)


	// Create difference vector
		// rotate 1
		// sub and equal

	// Mask unused values
		// multiply by mask_in 
		// rescale

	// Square
		// multiply x by x
		// rescale

	// Sum 2-by-2
		// rotate n/2
		// add 

	// Square root d°6 so 3 levels log6=2.9 {14./39,224./325,-(168./1625),448./40625,-(132./203125),2464./126953125,-(56./244140625)}
		// create X2       //rescale //mult_by_const
		// create X3=X2*X  //rescale //mult_by_const
		// create X4=X2*X2 //rescale //mult_by_const 
		// create X5=X3*X2 //rescale //mult_by_const
		// create X6=X3*X3 //rescale //mult_by_const
		// create X+c[0]

	// Mask
		// multiply by mask_out

	// Rotate and add
		// for j=0..log(pts):rot(2^j) add_and_equal

	// Decryption process + Decoding process
	valuesTest := encoder.Decode(decryptor.DecryptNew(ciphertext), ckkscontext.Slots())

	// Printing results and comparison
	fmt.Println()
	fmt.Printf("ValuesTest : %6f %6f %6f %6f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant : %6f %6f %6f %6f...\n", math.Pow(real(values[0]),2), math.Pow(real(values[1]),2), math.Pow(real(values[2]),2), math.Pow(real(values[3]),2))

}*/



func main() {
	mainfunk()
}
