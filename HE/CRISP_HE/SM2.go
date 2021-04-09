package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"
	"github.com/ldsec/lattigo/ckks"
	"os"
    "io"
    "log"
    "bufio"
	"encoding/csv"
	"strconv"
	"github.com/gonum/stat"
	"github.com/gonum/floats"
)
// Jan 2020, this codes computes a non linear cumulative billing function based on five levels and approximated by a deg 2 polynomial.

func printdebg(ckkscontext *ckks.CkksContext, encoder *ckks.Encoder, decryptor *ckks.Decryptor, ctIn *ckks.Ciphertext, string string) {
	valuesTest := encoder.Decode(decryptor.DecryptNew(ctIn), ckkscontext.Slots())
	fmt.Printf("Val %s: %6f %6f %6f %6f...%6f %6f %6f\n", string, valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3], valuesTest[int(ckkscontext.Slots()-3)], valuesTest[int(ckkscontext.Slots())-2], valuesTest[int(ckkscontext.Slots())-1])
}

func price(val float64) (cost float64){

	thr := [5]float64{2,4,6,8,10}
	dif := float64(2)
	coeff := [6]float64{0.2, 0.5, 1, 1.5, 2, 3}

	if (val < thr[0]){
		cost = coeff[0]*val
	}else if ((val>=thr[0])&&(val<thr[1])){
		cost = (coeff[0])*dif + coeff[1]*(val-thr[0])
	}else if ((val>=thr[1])&&(val<thr[2])){
		cost = (coeff[0]+coeff[1])*dif + coeff[2]*(val-thr[1])
	}else if ((val>=thr[2])&&(val<thr[3])){
		cost = (coeff[0]+coeff[1]+coeff[2])*dif + coeff[3]*(val-thr[2])
	}else if ((val>=thr[3])&&(val<thr[4])){
		cost = (coeff[0]+coeff[1]+coeff[2]+coeff[3])*dif + coeff[4]*(val-thr[3])
	}else{
		cost = (coeff[0]+coeff[1]+coeff[2]+coeff[3]+coeff[4])*dif + coeff[5]*(val-thr[4])
	}
	//cost = 0.0573*val*val + 0.1430*val + 0.0094
	return cost
}

func pricePol(val float64) (cost float64){
	cost = 0.0573*val*val + 0.1430*val + 0.0094
	return cost
}


func mainSM2() {
	rand.Seed(time.Now().UnixNano())

start := time.Now()
////////// Scheme params
	params := ckks.DefaultParams[122] 

	// Context
	var ckkscontext *ckks.CkksContext
	ckkscontext = ckks.NewCkksContext(params)

	encoder := ckkscontext.NewEncoder()

	// Keys
	kgen := ckkscontext.NewKeyGenerator()
	var sk *ckks.SecretKey
	var pk *ckks.PublicKey
	sk, pk = kgen.NewKeyPair()


	// Rotation key
	rotkeys := ckkscontext.NewRotationKeys()
	for i:=uint64(1); i <= ckkscontext.Slots()>>1; i <<= 1 {
		kgen.GenRot(ckks.RotationLeft, sk, i, rotkeys) 
	}

	// Relinearization key
	var rlk *ckks.EvaluationKey
	rlk = kgen.NewRelinKey(sk)

	// Encryptor
	var encryptor *ckks.Encryptor
	encryptor = ckkscontext.NewEncryptorFromPk(pk)

	// Decryptor
	var decryptor *ckks.Decryptor
	decryptor = ckkscontext.NewDecryptor(sk)

	// Evaluator
	var evaluator *ckks.Evaluator
	evaluator = ckkscontext.NewEvaluator()

// Time setup
t := time.Now()
t_init := float64(t.Sub(start))/1000000.0



////////// Import csv values for smart meter file in data_test/
start = time.Now()
	var conso []float64
	
	var file_str string
	if (len(os.Args)<2){
		file_str = "data_test/MAC000002.txt"
	}else {
		file_str = os.Args[1]
		fmt.Println(file_str)
	}

	csvFile, err_csv := os.Open(file_str)
	if err_csv != nil {
        log.Fatal("Unable to read input file " + file_str, err_csv)
    }
    defer csvFile.Close()

	reader := csv.NewReader(bufio.NewReader(csvFile))
	cnt :=0 
    for  {
        line, error := reader.Read()
        if error == io.EOF {
            break
        } else if error != nil {
            log.Fatal(error)
            print("error in line\n")
        }
        val, _ := strconv.ParseFloat(line[3],64)
        conso = append(conso,val)
        cnt++
    }
    fmt.Printf("number of lines: %d\n", cnt)
    fmt.Printf("len conso: %d\n", len(conso))
    nbr_of_ciphers := int64(math.Floor(float64(cnt)/float64(1344)))
    fmt.Printf("number  ciphers: %d\n", nbr_of_ciphers)


	// Create a series of input vectors
	var input_vec [][]complex128
	input_vec = make([][]complex128, nbr_of_ciphers)
	mask := make([]complex128, ckkscontext.Slots())
	in_mean := make([]float64, nbr_of_ciphers)
	in_std := make([]float64, nbr_of_ciphers)
	in_max := make([]float64, nbr_of_ciphers)
	in_min := make([]float64, nbr_of_ciphers)

	for i:= int64(0); i < nbr_of_ciphers; i++ {
		input_vec[i] = make([]complex128, ckkscontext.Slots())
	} 
	var res_pt []float64 
	res_pt = make([]float64, nbr_of_ciphers)

	var res_ptPol []float64 
	res_ptPol = make([]float64, nbr_of_ciphers)

	for i:= int64(0); i < nbr_of_ciphers; i++ {
		X := make([]float64, ckkscontext.Slots())
		for j:= int64(0); j < int64(1344); j++ { //ckkscontext.Slots()
			k := i*int64(1344)+j 
			if k < int64(cnt) {
				input_vec[i][j] = complex(conso[k], 0)
				X[j] = conso[k]
				res_pt[i] += price(conso[k])
				res_ptPol[i] += pricePol(conso[k])
			}
		}
		in_mean[i], in_std[i] = stat.MeanStdDev(X, nil)
		in_min[i] = floats.Min(X)
		in_max[i] = floats.Max(X)

	}

	for i :=int64(0); i < int64(1344); i++ {
		mask[i] = complex(1, 0)
	}
	for i :=int64(1344); i < int64(ckkscontext.Slots()); i++ {
		mask[i] = complex(0, 0)
	}

// Time import csv
t = time.Now()
t_csv := float64(t.Sub(start))/1000000.0



////////// Print parametrization
start = time.Now()
	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())
	//fmt.Printf("Values     : %6f -- %6f -- %6f -- %6f...\n", conso[0], conso[1], conso[2], conso[3])
	fmt.Println()

	// PlaintextS creation and encoding process
	plaintextS := make([]*ckks.Plaintext, nbr_of_ciphers)
	for i:= int64(0); i < nbr_of_ciphers; i++ {
		plaintextS[i] = ckkscontext.NewPlaintext(ckkscontext.Levels()-1, ckkscontext.Scale())
		encoder.Encode(plaintextS[i], input_vec[i], ckkscontext.Slots())
	} 
	
	// Encryption process
	ciphertextS := make([]*ckks.Ciphertext, nbr_of_ciphers)
	for i:= int64(0); i < nbr_of_ciphers; i++ {
		ciphertextS[i] = encryptor.EncryptNew(plaintextS[i])
	}
// Time encrypt
t = time.Now()
t_enc := float64(t.Sub(start))/1000000.0

////////// Adding to slot 0 for packed ct 
start = time.Now()
	for i:= int64(0); i < nbr_of_ciphers; i++ {
		ciphertextS[i] = evaluator.EvaluatePoly(ciphertextS[i], []float64 {0.0094,0.1430,0.0573}, rlk)

		plaint_mask := ckkscontext.NewPlaintext(ciphertextS[i].Level(), ciphertextS[i].Scale())
		encoder.Encode(plaint_mask, mask, ckkscontext.Slots())
		evaluator.MulRelin(plaint_mask,ciphertextS[i],nil,ciphertextS[i])
	}

cTmp := ckkscontext.NewCiphertext(1, ckkscontext.Levels()-1, ciphertextS[0].Scale())

	for i:= int64(0); i < nbr_of_ciphers; i++ {
		for j := uint64(1); j <= ckkscontext.Slots()>>1; j <<= 1 {
			evaluator.RotateColumns(ciphertextS[i], j, rotkeys, cTmp)
			evaluator.Add(cTmp, ciphertextS[i], ciphertextS[i].Ciphertext())
		}		
	} 

// Time computations
t = time.Now()
t_cmp := float64(t.Sub(start))/1000000.0


////////// Decryption process + Decoding process
start = time.Now()
	valuesTest := make([][]complex128, nbr_of_ciphers)
	for i:= int64(0); i < nbr_of_ciphers; i++ {
		valuesTest[i] = encoder.Decode(decryptor.DecryptNew(ciphertextS[i]), ckkscontext.Slots())
	}
// Time decrypt
t = time.Now()
t_dec := float64(t.Sub(start))/1000000.0


////////// Printing results and comparison
for i:= int64(0); i < nbr_of_ciphers; i++ {

		fmt.Printf("cipher %d\n", i)
		fmt.Printf("result : %6f\n", real(valuesTest[i][0]))
		fmt.Printf("benchR : %6f\n",res_pt[i])
		fmt.Printf("benchRPol : %6f\n",res_ptPol[i])
		fmt.Printf("error  : %6f \n", (real(valuesTest[i][0])-res_pt[i])/res_pt[i]*100)
		fmt.Printf("errorPol: %6f \n", (real(valuesTest[i][0])-res_ptPol[i])/res_ptPol[i]*100)
		fmt.Printf("mean  : %6f \n", in_mean[i])
		fmt.Printf("std  : %6f \n", in_std[i])
		fmt.Printf("min  : %6f \n", in_min[i])
		fmt.Printf("max  : %6f \n", in_max[i])
		fmt.Printf("t_init  : %6f \n", t_init)
		fmt.Printf("t_csv  : %6f \n", t_csv)
		fmt.Printf("t_enc  : %6f \n", t_enc)
		fmt.Printf("t_cmp  : %6f \n", t_cmp)
		fmt.Printf("t_dec  : %6f \n", t_dec)
		fmt.Println("")

		// Write to file
		f, err := os.OpenFile("Manjaro_resSM2Utils.csv", os.O_APPEND|os.O_WRONLY, 0644)
	    if err != nil {
	        fmt.Println(err)
	        return
	    }
	    newLine := file_str + fmt.Sprintf("%d",i) + "," + fmt.Sprintf("%d", ckkscontext.LogN()) + "," + fmt.Sprintf("%d", ckkscontext.LogQ()) + ","
	    newLine += fmt.Sprintf("%6f", res_pt[i]) + "," + fmt.Sprintf("%6f", res_ptPol[i]) + "," + fmt.Sprintf("%6f", real(valuesTest[i][0])) + "," + fmt.Sprintf("%6f", (real(valuesTest[i][0])-res_pt[i])/res_pt[i]*100) + "," + fmt.Sprintf("%6f", (real(valuesTest[i][0])-res_ptPol[i])/res_ptPol[i]*100) + ","
	    newLine += fmt.Sprintf("%2f", t_init) + "," + fmt.Sprintf("%2f", t_csv) + "," + fmt.Sprintf("%2f", t_enc) + "," + fmt.Sprintf("%2f", t_cmp) + "," + fmt.Sprintf("%2f", t_dec)
	    newLine += fmt.Sprintf("%6f", in_mean[i]) + "," + fmt.Sprintf("%6f", in_std[i]) + "," + fmt.Sprintf("%6f", in_min[i]) + "," + fmt.Sprintf("%6f", in_max[i])
	    _, err = fmt.Fprintln(f, newLine)
	    if err != nil {
	        fmt.Println(err)
	                f.Close()
	        return
	    }
	    err = f.Close()
	    if err != nil {
	        fmt.Println(err)
	        return
	    }


	}
}

func main() {
	mainSM2()
}

