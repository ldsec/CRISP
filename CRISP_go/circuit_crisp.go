package main

import (
	"encoding/hex"
	"fmt"

	"github.com/ldsec/CRISP-private/ring"
	"github.com/ldsec/CRISP-private/zkbpp"
	lr "github.com/ldsec/lattigo/ring"
	"github.com/ldsec/lattigo/utils"
)

func runCrisp() {

	//crisp circuit
	crispRing := ring.NewRing(zkbpp.DefaultParamsCRISP().Q())
	crispCircuit := zkbpp.NewCircuit(crispRing)

	//input generation
	params := zkbpp.DefaultParamsCRISP()

	//prng for Sampler
	prng, _ := utils.NewPRNG()

	//ternary with proba [1/3,1/3,1/3]
	ternarySamplerQ1 := lr.NewTernarySampler(prng, crispCircuit.Rq, float64(1)/3, false)
	//ternary with proba [1/4,1/2,1/4]
	ternarySamplerQ := lr.NewTernarySampler(prng, crispCircuit.Rq, 0.5, false)
	//uniformSampler
	uniformSampler := lr.NewUniformSampler(prng, crispCircuit.Rq)
	//gaussianSampler
	gaussianSamplerQ := lr.NewGaussianSampler(prng, crispCircuit.Rq, params.Sigma(), uint64(6*params.Sigma()))

	//keygen

	sk := ternarySamplerQ1.ReadNew()

	//pk = [-a*s + e, a]
	pk := [2]*lr.Poly{crispCircuit.Rq.NewPoly(), crispCircuit.Rq.NewPoly()}
	e := gaussianSamplerQ.ReadNew()
	pk[1] = uniformSampler.ReadNew()

	crispCircuit.Rq.MulCoeffs(sk, pk[1], pk[0])
	crispCircuit.Rq.Neg(pk[0], pk[0])
	crispCircuit.Rq.Add(pk[0], e, pk[0])

	//sample the encryption noises

	r0 := crispCircuit.Rq.NewPoly()
	e0 := crispCircuit.Rq.NewPoly()
	e1 := crispCircuit.Rq.NewPoly()

	ternarySamplerQ.Read(r0)
	gaussianSamplerQ.Read(e0)
	gaussianSamplerQ.Read(e1)

	//bdop parameters
	n := 1
	k := 5

	//rc sampling
	rc := make([]*lr.Poly, k)
	for j := 0; j < len(rc); j++ {
		rc[j] = crispCircuit.Rq.NewPoly()
		gaussianSamplerQ.Read(rc[j])
	}

	//public parameters, a1 and a2 sampling
	a1 := make([][]*lr.Poly, n)
	a2 := make([][]*lr.Poly, 3)
	uniformSamplerQ := lr.NewUniformSampler(prng, crispCircuit.Rq)
	//a1 coefficients
	for i := 0; i < len(a1); i++ {
		a1[i] = make([]*lr.Poly, 4)
		for j := 0; j < len(a1[i]); j++ {
			a1[i][j] = crispCircuit.Rq.NewPoly()
			uniformSamplerQ.Read(a1[i][j])
		}
	}

	//a2 coefficients
	for i := 0; i < len(a2); i++ {
		a2[i] = make([]*lr.Poly, 1)
		for j := 0; j < len(a2[i]); j++ {
			a2[i][j] = crispCircuit.Rq.NewPoly()
			uniformSamplerQ.Read(a2[i][j])
		}
	}

	//input formatting
	crispInputs := []zkbpp.ZKBVar{}
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(r0)...)
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(e0)...)
	crispInputs = append(crispInputs, crispCircuit.VarFromPoly(e1)...)
	for i := 0; i < k; i++ {
		crispInputs = append(crispInputs, crispCircuit.VarFromPoly(rc[i])...)
	}

	//message to encrypt
	message := []uint64{1, 2, 3, 4, 5}
	for i := 0; i < len(message); i++ {
		crispInputs = append(crispInputs, crispCircuit.VarUint64(message[i]))
	}

	crispCircuitDescription := func(input []zkbpp.ZKBVar) (output []zkbpp.ZKBVar) {

		//run CRISP

		//reconstruct Rq var
		r0Var := crispCircuit.RqVarFromZqArray(input[0:crispCircuit.Rq.N])
		e0Var := crispCircuit.RqVarFromZqArray(input[crispCircuit.Rq.N : 2*crispCircuit.Rq.N])
		e1Var := crispCircuit.RqVarFromZqArray(input[2*crispCircuit.Rq.N : 3*crispCircuit.Rq.N])
		rcVar := make([]zkbpp.ZKBVar, k)
		for i := 0; i < k; i++ {
			rcVar[i] = crispCircuit.RqVarFromZqArray(input[uint64(3+i)*crispCircuit.Rq.N : uint64(4+i)*crispCircuit.Rq.N])
		}

		messageVar := input[uint64(3+k)*crispCircuit.Rq.N:]

		//run circuit
		ct0, ct1, bdop1, bdop2, h := crispCircuit.MpcCRISP(r0Var, e0Var, e1Var, messageVar, rcVar, a1, a2, pk)

		//format output
		//ciphertext slots 0 and 1
		//bdop1 slots 2 to 2+(n-1)
		//bdop2 slot 2+n, 2+n+1, 2+n+2
		//hash slot 2+n+3 until the end
		//bdop1 is n, which is public, bdop2 is 3, hash is messageLen, also public
		output = make([]zkbpp.ZKBVar, 2+n+3+len(messageVar))
		output[0] = ct0
		output[1] = ct1

		for i := 0; i < n; i++ {
			output[2+i] = bdop1[i]
		}

		for i := 0; i < 3; i++ {
			output[2+n+i] = bdop2[i]
		}

		for i := 0; i < len(messageVar); i++ {
			output[2+n+3+i] = h[i]
		}

		return
	}
	crispCircuit.SetDescription(crispCircuitDescription)

	circuit := crispCircuit
	inputs := crispInputs

	//generate proof and verify it for a given circuit
	nbIterations := 229
	nbOpenings := 148

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
	fmt.Println("Proof is ", v)

	ct0, ct1 := output[0], output[1]
	bdop1 := output[2]
	bdop2 := output[3:6]
	hash := output[6:]

	fmt.Println("Original message : ")
	fmt.Println(message)

	fmt.Println()
	fmt.Println()

	fmt.Println("Decrypted output : ")
	pt := crispCircuit.CKKSDecrypt(ct0.RqValue, ct1.RqValue, sk)
	fmt.Println(crispCircuit.Rq.PolyToString(pt)[:len(message)])

	fmt.Println()
	fmt.Println()

	fmt.Println("Noises to remove: ")
	tmp := crispCircuit.Rq.NewPoly()
	tmp2 := crispCircuit.Rq.NewPoly()
	crispCircuit.Rq.MulCoeffs(e1, sk, tmp)
	crispCircuit.Rq.MulCoeffs(e, r0, tmp2)
	crispCircuit.Rq.Add(tmp2, e0, tmp2)
	crispCircuit.Rq.Add(tmp, tmp2, tmp2)
	fmt.Println(crispCircuit.Rq.PolyToString(tmp2)[:len(message)])
	crispCircuit.Rq.Sub(pt, tmp2, tmp2)
	fmt.Println()
	fmt.Println("Decryption - noises: ")
	fmt.Println(crispCircuit.Rq.PolyToString(tmp2)[:len(message)])

	fmt.Println()
	fmt.Println()

	fmt.Println("SHA-256 :")
	for i := 0; i < len(hash); i++ {
		buf := make([]byte, 32)
		mpcSha := hash[i].Z2Value.FillBytes(buf)
		fmt.Println(hex.EncodeToString(mpcSha))
	}
	fmt.Println()
	fmt.Println()

	fmt.Println("First coeffs of BDOP commitment : ")
	fmt.Println(crispCircuit.Rq.PolyToString(bdop1.RqValue)[0])
	for i := 0; i < len(bdop2); i++ {
		fmt.Println(crispCircuit.Rq.PolyToString(bdop2[i].RqValue)[0])
	}

}
