package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ldsec/CRISP-private/ring"
	"github.com/ldsec/CRISP-private/zkbpp"
)

func runShaCircuit() {

	//sha circuit
	shaRing := ring.NewRing(big.NewInt(256)) // ring for one ascii char
	shaCircuit := zkbpp.NewCircuit(shaRing)
	shaCircuitDescription := func(input []zkbpp.ZKBVar) (output []zkbpp.ZKBVar) {

		//input renaming for convenience
		a := input[0]

		output = make([]zkbpp.ZKBVar, 2)

		output[1] = shaCircuit.MpcBitDec(a)
		output[0] = shaCircuit.MpcZ2ShaFast(output[1])

		return
	}
	shaCircuit.SetDescription(shaCircuitDescription)
	shaInputs := []zkbpp.ZKBVar{shaCircuit.VarUint64(42)} // code for "*" character

	//choose the circuit
	circuit := shaCircuit
	inputs := shaInputs

	nbIterations := 229
	nbOpenings := 148
	// nbIterations = 1
	// nbOpenings = 0

	fmt.Println("##################### PREPROCESS START ################")
	ctx, kkwP := zkbpp.Preprocess(circuit, inputs, nbIterations)
	opened, closed := zkbpp.PreprocessChallenge(nbIterations, nbOpenings)
	fmt.Println("Requested iterations are :", opened)
	fmt.Println("Closed iterations are :", closed)
	fmt.Println("###################### PREPROCESS END #################")
	fmt.Println()
	fmt.Println("##################### PROOF START ################")
	p, output := zkbpp.Prove(circuit, inputs, ctx, opened, closed)
	fmt.Println("###################### PROOF END #################")
	fmt.Println()
	fmt.Println("##################### VERIF START ################")
	v := zkbpp.Verify(p, kkwP, opened, closed)
	fmt.Println("###################### VERIF END #################")

	//shaCircuit outputs
	fmt.Println("Proof is ", v)

	buf := make([]byte, 32)

	mpc_sha := output[0].Z2Value.FillBytes(buf)
	std_sha := shaCircuit.Sha(output[1].Z2Value)
	fmt.Println()
	fmt.Println("MPC SHA-256 is : ", hex.EncodeToString(mpc_sha))
	fmt.Println("REF SHA-256 is : ", hex.EncodeToString(std_sha.FillBytes(buf)))
}
