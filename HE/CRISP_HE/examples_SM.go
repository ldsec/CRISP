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
)

func mainSM() {
	rand.Seed(time.Now().UnixNano())

start := time.Now()
////////// Scheme params
	params := ckks.DefaultParams[11] //11: {11, []uint8{31, 25, 25}, []uint8{45}, 1 << 35, 3.2}, // not secure
	// 11: {11, []uint8{45}, []uint8{45}, 1 << 25, 3.2}, check relin key not used thus logQ 45
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
    nbr_of_ciphers := int64(math.Floor(float64(cnt)/float64(ckkscontext.Slots()))+1)
    fmt.Printf("number  ciphers: %d\n", nbr_of_ciphers)


	// Create a series of input vectors
	var input_vec [][]complex128
	input_vec = make([][]complex128, nbr_of_ciphers)
	for i:= int64(0); i < nbr_of_ciphers; i++ {
		input_vec[i] = make([]complex128, ckkscontext.Slots())
	} 
	var res_pt float64 
	for i:= int64(0); i < nbr_of_ciphers; i++ {
		for j:= int64(0); j < int64(ckkscontext.Slots()); j++ {
			k := i*int64(ckkscontext.Slots())+j 
			if k < int64(cnt) {
				input_vec[i][j] = complex(conso[k], 0)
				res_pt += real(input_vec[i][j])
			}
		}
	}
// Time import csv
t = time.Now()
t_csv := float64(t.Sub(start))/1000000.0



////////// Print parametrization
start = time.Now()
	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())
	fmt.Printf("Values     : %6f -- %6f -- %6f -- %6f...\n", conso[0], conso[1], conso[2], conso[3])
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
	cTmp := ckkscontext.NewCiphertext(1, ckkscontext.Levels()-1, ckkscontext.Scale())
	for i:= int64(0); i < nbr_of_ciphers; i++ {//-1
		for j := uint64(1); j <= ckkscontext.Slots()>>1; j <<= 1 {
			evaluator.RotateColumns(ciphertextS[i], j, rotkeys, cTmp)
			evaluator.Add(cTmp, ciphertextS[i], ciphertextS[i].Ciphertext())
		}		
	} 

	// Add ciphertexts together to cipher0
	for i:= int64(1); i < nbr_of_ciphers; i++ {
		evaluator.Add(ciphertextS[0],ciphertextS[i],ciphertextS[0])
	}
// Time computations
t = time.Now()
t_cmp := float64(t.Sub(start))/1000000.0



////////// Decryption process + Decoding process
start = time.Now()
	valuesTest := encoder.Decode(decryptor.DecryptNew(ciphertextS[0]), ckkscontext.Slots())
// Time decrypt
t = time.Now()
t_dec := float64(t.Sub(start))/1000000.0


////////// Printing results and comparison
	fmt.Printf("result : %6f\n", real(valuesTest[0]))
	fmt.Printf("benchR : %6f\n",res_pt)
	fmt.Printf("error  : %6f \n", (real(valuesTest[0])-res_pt)/res_pt*100)
	fmt.Printf("t_init  : %6f \n", t_init)
	fmt.Printf("t_csv  : %6f \n", t_csv)
	fmt.Printf("t_enc  : %6f \n", t_enc)
	fmt.Printf("t_cmp  : %6f \n", t_cmp)
	fmt.Printf("t_dec  : %6f \n", t_dec)

	// Write to file
	f, err := os.OpenFile("Manjaro_resSMUtils.csv", os.O_APPEND|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Println(err)
        return
    }
    newLine := file_str + "," + fmt.Sprintf("%d", ckkscontext.LogN()) + "," + fmt.Sprintf("%d", ckkscontext.LogQ()) + ","
    newLine += fmt.Sprintf("%d", cnt) + "," + fmt.Sprintf("%6f", res_pt) + "," + fmt.Sprintf("%6f", real(valuesTest[0])) + "," + fmt.Sprintf("%6f", (real(valuesTest[0])-res_pt)/res_pt*100) + ","
    newLine += fmt.Sprintf("%2f", t_init) + "," + fmt.Sprintf("%2f", t_csv) + "," + fmt.Sprintf("%2f", t_enc) + "," + fmt.Sprintf("%2f", t_cmp) + "," + fmt.Sprintf("%2f", t_dec)
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

func main() {
	mainSM()
}
