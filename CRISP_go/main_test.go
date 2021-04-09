package main

import (
	"math/big"
	"testing"

	. "github.com/ldsec/CRISP-private/ring"
	"github.com/ldsec/CRISP-private/zkbpp"
)

func setupDummy() (*zkbpp.Circuit, []zkbpp.ZKBVar) {
	dummyRing := NewRing(big.NewInt(256))
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

	a := dummyCircuit.VarUint64(41)
	b := dummyCircuit.VarUint64(3)
	c := dummyCircuit.VarUint64(5)

	return dummyCircuit, []zkbpp.ZKBVar{a, b, c}
}

func setupSha() (*zkbpp.Circuit, []zkbpp.ZKBVar) {
	shaRing := NewRing(big.NewInt(256))
	shaCircuit := zkbpp.NewCircuit(shaRing)

	shaCircuitDescription := func(input []zkbpp.ZKBVar) (output []zkbpp.ZKBVar) {

		//input renaming for convenience
		a := input[0]

		output = make([]zkbpp.ZKBVar, 1)

		b := shaCircuit.MpcBitDec(a)
		output[0] = shaCircuit.MpcZ2ShaFast(b)

		return
	}

	shaCircuit.SetDescription(shaCircuitDescription)

	a := shaCircuit.VarUint64(42)

	return shaCircuit, []zkbpp.ZKBVar{a}
}

func BenchmarkPreprocessing(b *testing.B) {
	circuit, input := setupDummy()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zkbpp.Preprocess(circuit, input, 229)
	}
}
func BenchmarkProof(b *testing.B) {
	circuit, input := setupDummy()
	ctx, _ := zkbpp.Preprocess(circuit, input, 229)
	open, closed := zkbpp.PreprocessChallenge(229, 148)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zkbpp.Prove(circuit, input, ctx, open, closed)
	}
}

func BenchmarkVerification(b *testing.B) {
	circuit, input := setupDummy()
	ctx, kkwP := zkbpp.Preprocess(circuit, input, 229)
	open, closed := zkbpp.PreprocessChallenge(229, 148)
	p, _ := zkbpp.Prove(circuit, input, ctx, open, closed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zkbpp.Verify(p, kkwP, open, closed)
	}
}

func BenchmarkPreprocessingSha(b *testing.B) {
	circuit, input := setupSha()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zkbpp.Preprocess(circuit, input, 229)
	}
}
func BenchmarkProofSha(b *testing.B) {
	circuit, input := setupSha()
	ctx, _ := zkbpp.Preprocess(circuit, input, 229)
	open, closed := zkbpp.PreprocessChallenge(229, 148)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zkbpp.Prove(circuit, input, ctx, open, closed)
	}
}

func BenchmarkVerificationSha(b *testing.B) {
	circuit, input := setupSha()
	ctx, kkwP := zkbpp.Preprocess(circuit, input, 229)
	open, closed := zkbpp.PreprocessChallenge(229, 148)
	p, _ := zkbpp.Prove(circuit, input, ctx, open, closed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		zkbpp.Verify(p, kkwP, open, closed)
	}
}
