package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"
	"github.com/ldsec/lattigo/ckks"
	"github.com/ldsec/lattigo/ring"
	"os"
    "io"
    "log"
    "bufio"
	"encoding/csv"
	"strconv"
)

func printdebg(ckkscontext *ckks.CkksContext, encoder *ckks.Encoder, decryptor *ckks.Decryptor, ctIn *ckks.Ciphertext, string string) {
	valuesTest := encoder.Decode(decryptor.DecryptNew(ctIn), ckkscontext.Slots())
	fmt.Printf("Val %s: %6f %6f %6f %6f...%6f %6f %6f\n", string, valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3], valuesTest[int(ckkscontext.Slots()/2)], valuesTest[int(ckkscontext.Slots()/2)+1], valuesTest[int(ckkscontext.Slots()/2)+2])
}

func getCommonPrefix(input []float64) (prefix float64) {
	digits := 0
	pref := input[0]
	for int(pref) > 0 {
		pref /= 10
		digits = digits +1
	} 
	prefix = math.Floor(input[0]/math.Pow(10,float64(digits-1)))
	prefix_test := prefix
	prefix = 0
	for i:=digits-1; i>=0; i-- {
		for _, j := range input {
			if (math.Floor(j/math.Pow(10,float64(i))) != prefix_test) {
				return prefix*math.Pow(10,float64(i+1))
			}
		}
		prefix_test = math.Floor(input[0]/math.Pow(10,float64(i-1)))
		prefix = math.Floor(input[0]/math.Pow(10,float64(i)))
	}
	return 0
}

func distance(X, Y, T []float64) (dist, vmax float64, norm_i []float64){
	nbr_pts := len(X)
	norm_i = make([]float64, nbr_pts-1)
	if (nbr_pts!=len(Y))||(nbr_pts!=len(T)) {
		panic("incoherent input size XYT")
	}

	dist = 0
	vmax = 0
	var subd float64 
	for i:=0; i<nbr_pts-1; i++ {
		subd = math.Sqrt(math.Pow(X[i]-X[i+1],2) + math.Pow(Y[i]-Y[i+1],2))
		if (T[i+1]-T[i])>0 {
			vmax = math.Max(vmax,subd/(T[i+1]-T[i]))
		}else{
			panic("equal timestamps")
		}
		dist += subd
	} 
	if (vmax <= 2){
		vmax = 2;
	}else if ((vmax>2)&&(vmax<=5)){
		vmax = 5;
	}else if ((vmax>5)&&(vmax<=7)){
		vmax = 7;
	}else if ((vmax>7)&&(vmax<=10)){
		vmax = 10;
	}else if ((vmax>10)&&(vmax<=15)){
		vmax = 15;
	}else if ((vmax>15)&&(vmax<=20)){
		vmax = 20;
	}else{
		vmax = 100;
		panic("WARNING: Vmax could not be found - set to 100 m/s")
	}

	for i:=0; i<nbr_pts-1; i++ {
		if (T[i+1]-T[i])>0 {
			norm_i[i] = (vmax)*(T[i+1]-T[i])/math.Sqrt(14);
		}else{
			norm_i[i] = 1
		}
	}
	return dist, vmax, norm_i
}

func mainDist() {
	rand.Seed(time.Now().UnixNano())

////////// Scheme params
start := time.Now()
	params := ckks.DefaultParams[13] //13: {13, []uint8{20, 20, 21, 21, 21, 21, 21, 21, 21}, []uint8{30}, 1 << 21, 3.2},
	// 13: {13, []uint8{22, 22, 22, 22, 22, 22, 22, 22}, []uint8{31}, 1 << 22, 3.2} working if truncate the data 

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
	var rlk *ckks.EvaluationKey
	rlk = kgen.NewRelinKey(sk)

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



////////// Import location values for file in data_test/
start = time.Now()
	var Easting []float64
	var Northing []float64
	var TimeVec []float64

	var file_str string
	if (len(os.Args)<2){
		file_str = "data_test/1-20131209181436.txt" //1-20131209181436
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
        valX, _ := strconv.ParseFloat(line[0],64)
        valY, _ := strconv.ParseFloat(line[1],64)
        valT, _ := strconv.ParseFloat(line[2],64)
        Easting = append(Easting,valX)
        Northing = append(Northing,valY)
        TimeVec = append(TimeVec,valT)
        cnt++
    }
    fmt.Printf("number of lines: %d\n", cnt)

	// Get plaintext computation results
    var vmax float64
    var res_pt float64
    var norm_i []float64
    res_pt,vmax, norm_i = distance(Easting, Northing, TimeVec)
    _=vmax
    _=norm_i

	// Values to encrypt
	values := make([]complex128, ckkscontext.Slots())
	mask := make([]complex128, ckkscontext.Slots())
	mask_Out := make([]complex128, ckkscontext.Slots())
	for i:=uint64(0); i<ckkscontext.Slots(); i++ {
		mask[i] = 0
		mask_Out[i] = 0
	} 

	prefix_North := getCommonPrefix(Northing)
	prefix_East := getCommonPrefix(Easting)
	fmt.Printf("prefix north = %d\n",int(prefix_North))
	fmt.Printf("prefix north = %d\n",int(prefix_East))

	for i :=0; i < cnt; i++ {
		values[i] = complex(Easting[i]-prefix_East, 0)//complex(Easting[i], 0)
		values[int(ckkscontext.Slots()/2)+i] = complex(Northing[i]-prefix_North, 0)
	}
	for i :=0; i < cnt-1; i++ {
		mask[i] = complex(1/norm_i[i],0)
		mask[int(ckkscontext.Slots()/2.0)+i] = complex(1/norm_i[i],0)
		mask_Out[i] = complex(norm_i[i],0)
	}
// Time import csv
t = time.Now()
t_csv := float64(t.Sub(start))/1000000.0


////////// Print parametrization
start = time.Now()
	fmt.Printf("HEAAN parameters : logN = %d, logQ = %d, levels = %d, scale= %f, sigma = %f \n", ckkscontext.LogN(), ckkscontext.LogQ(), ckkscontext.Levels(), ckkscontext.Scale(), ckkscontext.Sigma())
	fmt.Println()

	// Plaintext creation and encoding process
	plaintext := ckkscontext.NewPlaintext(ckkscontext.Levels()-1, ckkscontext.Scale())
	encoder.Encode(plaintext, values, ckkscontext.Slots())

	// Encryption process
	var ciphertext *ckks.Ciphertext
	ciphertext = encryptor.EncryptNew(plaintext)
	//printdebg(ckkscontext, encoder, decryptor, ciphertext, "input")
// Time encrypt
t = time.Now()
t_enc := float64(t.Sub(start))/1000000.0


////////// Computations
start = time.Now()
	// Create difference vector
	cTmp := ckkscontext.NewCiphertext(1, ckkscontext.Levels()-1, ckkscontext.Scale())
	evaluator.RotateColumns(ciphertext,1,rotkeys,cTmp)
	evaluator.Sub(cTmp,ciphertext,ciphertext)

	// Mask unused values
	plaint_mask := ckkscontext.NewPlaintext(ciphertext.Level(), float64(ckkscontext.Moduli()[ciphertext.Level()]))
	encoder.Encode(plaint_mask, mask, ckkscontext.Slots())
	evaluator.MulRelin(plaint_mask,ciphertext,nil,ciphertext)
	evaluator.Rescale(ciphertext,ckkscontext.Scale(),ciphertext)

	// Square
	evaluator.MulRelin(ciphertext,ciphertext,rlk,ciphertext)
	evaluator.Rescale(ciphertext,ckkscontext.Scale(),ciphertext)

	// Sum 2-by-2
	evaluator.RotateColumns(ciphertext,uint64(ckkscontext.Slots()/2),rotkeys,cTmp)
	evaluator.Add(ciphertext,cTmp,ciphertext) 

	// Evaluate Square root
	ciphertext = evaluator.EvaluatePoly(ciphertext, []float64 {16.0/51,336.0/425,-(336.0/2125),1232.0/53125,-(528.0/265625),16016.0/166015625,-(10192.0/4150390625),528.0/20751953125}, rlk)
	// d7 {16.0/51,336.0/425,-(336.0/2125),1232.0/53125,-(528.0/265625),16016.0/166015625,-(10192.0/4150390625),528.0/20751953125}
	// Mask
	plaint_mask_Out := ckkscontext.NewPlaintext(ciphertext.Level(), float64(ckkscontext.Moduli()[ciphertext.Level()]))
	encoder.Encode(plaint_mask_Out, mask_Out, ckkscontext.Slots())
	evaluator.MulRelin(plaint_mask_Out,ciphertext,nil,ciphertext)

// Time computations
t = time.Now()
t_cmp := float64(t.Sub(start))/1000000.0


////////// Decryption process + Decoding process
start = time.Now()
	var plainResult *ckks.Plaintext
	plainResult = decryptor.DecryptNew(ciphertext)

	pTmp := ckkscontext.ContextQ().NewPoly()
	for i := uint64(1); i < ckkscontext.Slots(); i <<= 1 {
		ring.PermuteNTT(plainResult.Value()[0], ring.ModExp(uint64(5), i, 4*ckkscontext.Slots()), pTmp)
		ckkscontext.ContextQ().AddLvl(plainResult.Level(), plainResult.Value()[0], pTmp, plainResult.Value()[0])
	}

	valuesTest := encoder.Decode(plainResult, ckkscontext.Slots())
// Time decrypt
t = time.Now()
t_dec := float64(t.Sub(start))/1000000.0


////////// Printing results and comparison
	var maxval float64
	for _,i := range valuesTest {
		maxval = math.Max(maxval, math.Abs(real(i)))
	}
	fmt.Printf("result : %6f\n", real(valuesTest[0]))
	fmt.Printf("benchR : %6f\n",res_pt)
	fmt.Printf("error  : %6f \n", (real(valuesTest[0])-res_pt)/res_pt*100)
	fmt.Printf("t_init  : %6f \n", t_init)
	fmt.Printf("t_csv  : %6f \n", t_csv)
	fmt.Printf("t_enc  : %6f \n", t_enc)
	fmt.Printf("t_cmp  : %6f \n", t_cmp)
	fmt.Printf("t_dec  : %6f \n", t_dec)
////////// Write to file
f, err := os.OpenFile("Manjaro_resDistUtils.csv", os.O_APPEND|os.O_WRONLY, 0644)
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
	mainDist()
}
