package main

import (
	"fmt"
	//"math"
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

func mainDS() {
	rand.Seed(time.Now().UnixNano())

start := time.Now()
////////// Scheme params
	params := ckks.DefaultParams[12] // 12: {12, []uint8{31, 25}, []uint8{40}, 1 << 25, 3.2},

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



////////// Import csv values for SNPs file in data_test/
start = time.Now()
	var conso []float64

	var file_str string
	if (len(os.Args)<2){
		file_str = "data_test/HG01879Alzheimervec.txt"
	}else {
		file_str = "Genomics/vec/"+os.Args[1]+"vec.txt"
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
        val, _ := strconv.ParseFloat(line[0],64)
        conso = append(conso,val)
        cnt++
    }
    fmt.Printf("number of lines: %d\n", cnt)

    // Import SNPs weights 
	var weights []float64
	var norm_factor float64
	var vec_str string
	if (len(os.Args)<2){
		vec_str = "data_test/HG01879Alzheimerweight.txt"
	}else {
		vec_str = "Genomics/weights/"+os.Args[1]+"weight.txt"
		fmt.Println(vec_str)
	}

	csvFileWeights, errW_csv := os.Open(vec_str)
	if errW_csv != nil {
        log.Fatal("Unable to read weights file " + vec_str, err_csv)
    }
    defer csvFileWeights.Close()
	readerWeights := csv.NewReader(bufio.NewReader(csvFileWeights))
    for  {
        lineWeights, errorW := readerWeights.Read()
        if errorW == io.EOF {
            break
        } else if errorW != nil {
            log.Fatal(errorW)
            print("error in line W\n")
        }
        valWeight, _ := strconv.ParseFloat(lineWeights[0],64)
        weights = append(weights,valWeight)
        norm_factor += valWeight
    }

	// Values to encrypt
	values := make([]complex128, ckkscontext.Slots())
	var res_pt float64 
	mask := make([]complex128, ckkscontext.Slots())
	for i :=0; i < cnt; i++ {
		values[i] = complex(conso[i], 0)//complex(conso[i], 0)
		res_pt += real(values[i])*weights[i]/norm_factor
		mask[i] = complex(weights[i]/norm_factor,0)
	}
// Time import csv
t = time.Now()
t_csv := float64(t.Sub(start))/1000000.0


////////// Print parametrization
start = time.Now()
	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())
	fmt.Printf("Values     : %6f %6f %6f %6f...\n", values[0], values[1], values[2], values[3])
	fmt.Println()

	// Plaintext creation and encoding process
	plaintext := ckkscontext.NewPlaintext(ckkscontext.Levels()-1, ckkscontext.Scale())
	encoder.Encode(plaintext, values, ckkscontext.Slots())

	// Encryption process
	var ciphertext *ckks.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)
// Time encrypt
t = time.Now()
t_enc := float64(t.Sub(start))/1000000.0


////////// Mask the vector
start = time.Now()
	plaint_mask := ckkscontext.NewPlaintext(ciphertext.Level(), ciphertext.Scale())
	encoder.Encode(plaint_mask, mask, ckkscontext.Slots())
	evaluator.MulRelin(plaint_mask,ciphertext,nil,ciphertext)
	
	// Sum to slot 0
	for j := uint64(1); j <= ckkscontext.Slots()>>1; j <<= 1 {	
		cTmp := evaluator.RotateColumnsNew(ciphertext, j, rotkeys)
		evaluator.Add(cTmp, ciphertext, ciphertext)
	}
// Time computations
t = time.Now()
t_cmp := float64(t.Sub(start))/1000000.0



////////// Decryption process + Decoding process
start = time.Now()
	valuesTest := encoder.Decode(decryptor.DecryptNew(ciphertext), ckkscontext.Slots())
// Time decrypt
t = time.Now()
t_dec := float64(t.Sub(start))/1000000.0


	// Printing results and comparison
	fmt.Printf("result : %6f\n", real(valuesTest[0]))
	fmt.Printf("benchR : %6f\n",res_pt)
	fmt.Printf("error  : %6f \n", (real(valuesTest[0])-res_pt)/res_pt*100)
	fmt.Printf("t_init  : %6f \n", t_init)
	fmt.Printf("t_csv  : %6f \n", t_csv)
	fmt.Printf("t_enc  : %6f \n", t_enc)
	fmt.Printf("t_cmp  : %6f \n", t_cmp)
	fmt.Printf("t_dec  : %6f \n", t_dec)

	// Save to file
	f, err := os.OpenFile("Manjaro_resDSUtils.csv", os.O_APPEND|os.O_WRONLY, 0644)
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
	mainDS()
}
