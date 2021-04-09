package main

import (
	"fmt"
	"math/big"

	"github.com/ldsec/CRISP-private/ring"
	"github.com/ldsec/CRISP-private/zkbpp"
)

func runDummyCircuit() {

	//dummy circuit
	dummyRing := ring.NewRing(big.NewInt(256))
	dummyCircuit := zkbpp.NewCircuit(dummyRing)
	dummyCircuitDescription := func(input []zkbpp.ZKBVar) (output []zkbpp.ZKBVar) {
		// f(a, b, c) = a*a + b*b - 2*a*b*c - K

		//input renaming for convenience
		a := input[0]
		b := input[1]
		c := input[2]

		//k setup
		k := big.NewInt(12)

		aa := dummyCircuit.MpcMult(a, a) //a*a

		bb := dummyCircuit.MpcMult(b, b) //b*b

		a2 := dummyCircuit.MpcMultK(a, big.NewInt(2)) //2*a
		bc := dummyCircuit.MpcMult(b, c)              //b*c

		abc2 := dummyCircuit.MpcMult(a2, bc) //2*a*b*c

		lhs := dummyCircuit.MpcAdd(aa, bb)   //a*a + b*b
		rhs := dummyCircuit.MpcAddK(abc2, k) //2*a*b*c + K

		output = make([]zkbpp.ZKBVar, 1)

		output[0] = dummyCircuit.MpcSub(lhs, rhs)

		return
	}
	dummyCircuit.SetDescription(dummyCircuitDescription)
	dummyInputs := []zkbpp.ZKBVar{dummyCircuit.VarUint64(41), dummyCircuit.VarUint64(3), dummyCircuit.VarUint64(4)}

	//choose the circuit
	circuit := dummyCircuit
	inputs := dummyInputs

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

	//dummyCircuit outputs
	fmt.Println("Circuit output Zq : ", output[0].Value)
	fmt.Println("Proof is ", v)
}
