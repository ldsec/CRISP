package zkbpp

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	mr "math/rand"
	"time"

	lr "github.com/ldsec/lattigo/ring"
	"github.com/ldsec/lattigo/utils"
)

//Security level of seeds, in bytes. 128 bits = 16 bytes, 256 bits = 32 bytes
const SECURITY_LEVEL = 16

//ZKBProof is a struct holding a ZKBProof with cut&choose preprocessing
type ZKBProof struct {
	nbIterations int
	c            *Circuit
	inputSize    int

	e   []int
	bs  []b
	zs  []z
	y   [][]*big.Int
	rqY [][]*lr.Poly
	z2Y [][]*big.Int

	//KKW

	//open iterations
	omegaCom [][sha256.Size]byte
	kkwSeeds [][]byte
	salt     []byte

	//closed iterations additionnal
	seedCom     [][sha256.Size]byte
	deltas      [][]*big.Int
	gammaRand   [][]byte
	inputOffset [][]*big.Int
	omegaRand   [][]byte
}

//KKWProof is a struct holding the first round of commitment for a cut & choose protocol
type KKWProof struct {
	hGamma [sha256.Size]byte
	hOmega [sha256.Size]byte
}

//b holds the seeds and output share of player e+2
type b struct {
	ye2   []*big.Int
	rqYe2 []*lr.Poly
	z2Ye2 []*big.Int
	ce2   [sha256.Size]byte
}

//z holds the views for player e+1, seeds for player e and e+1 and offset for the third share
type z struct {
	viewe1   []*big.Int
	rqViewe1 []*lr.Poly
	seeds    [2][]byte
	x3Offset []*big.Int
}

//a holds all outputshares and commits for ZKCE
type a struct {
	outputShares   [3][]*big.Int
	rqOutputShares [3][]*lr.Poly
	z2OutputShares [3][]*big.Int
	commits        [3][sha256.Size]byte
}

//KKWContext is a struct holding the information needed from the preprocessing phase
type KKWContext struct {
	nbIterations int
	offsets      []offset
	seeds        [][]byte
	omegaRand    [][]byte
	gammaRand    [][]byte
	omegaCom     [][sha256.Size]byte
	salt         []byte
	gammaiCom    [][3][sha256.Size]byte
}

//Preprocess runs the preprocessing of a ZKB++ proof on a circuit c with input input for nbIterations.
//Returns a KKWContext for the main proof, and a KKWProof for the preprocessing commitment
func Preprocess(c *Circuit, input []ZKBVar, nbIterations int) (ctx *KKWContext, p KKWProof) {
	//masterSeed := []byte{43}
	masterSeed := make([]byte, SECURITY_LEVEL)
	rand.Read(masterSeed)
	masterPRNG, _ := utils.NewKeyedPRNG(masterSeed)

	//prepare context
	ctx = &KKWContext{
		nbIterations: nbIterations,
		offsets:      make([]offset, nbIterations),
		seeds:        make([][]byte, nbIterations),
		omegaRand:    make([][]byte, nbIterations),
		gammaRand:    make([][]byte, nbIterations),
		salt:         make([]byte, SECURITY_LEVEL),
		omegaCom:     make([][sha256.Size]byte, nbIterations),
		gammaiCom:    make([][3][sha256.Size]byte, nbIterations),
	}

	randomness := make([]byte, SECURITY_LEVEL)
	masterPRNG.Clock(ctx.salt)

	omegaCom := make([]byte, 0)
	gammaCom := make([]byte, 0)

	//generate triples and commit to it
	for i := 0; i < nbIterations; i++ {
		iterationSeed := make([]byte, SECURITY_LEVEL)
		masterPRNG.Clock(iterationSeed)
		iterationPrng, _ := utils.NewKeyedPRNG(iterationSeed)
		c.preprocess(input, iterationPrng)
		ctx.offsets[i] = c.preprocessing
		ctx.seeds[i] = iterationSeed

		//commit to input offset (phi)
		masterPRNG.Clock(randomness)
		inputOffsetCom := computeOffsetCommit(c.preprocessing.phis, randomness, ctx.salt)
		omegaCom = append(omegaCom, inputOffsetCom[:]...)
		ctx.omegaCom[i] = inputOffsetCom

		//save randomness for proof
		ctx.omegaRand[i] = make([]byte, SECURITY_LEVEL)
		copy(ctx.omegaRand[i], randomness)

		//commit to triples offset (delta)
		iterationPrng.Clock(randomness)
		triplesOffsetCom := computeOffsetCommit(c.preprocessing.deltas, randomness, ctx.salt)

		//save randomness for proof
		ctx.gammaRand[i] = make([]byte, SECURITY_LEVEL)
		copy(ctx.gammaRand[i], randomness)

		//commit to player seed
		c.rand[0].Clock(randomness)
		seed1Com := computeSeedCommit(c.seeds[0], randomness, ctx.salt)
		ctx.gammaiCom[i][0] = seed1Com
		c.rand[1].Clock(randomness)
		seed2Com := computeSeedCommit(c.seeds[1], randomness, ctx.salt)
		ctx.gammaiCom[i][1] = seed2Com
		c.rand[2].Clock(randomness)
		seed3Com := computeSeedCommit(c.seeds[2], randomness, ctx.salt)
		ctx.gammaiCom[i][2] = seed3Com

		iterationCom := hash(triplesOffsetCom[:], seed1Com[:], seed2Com[:], seed3Com[:])

		gammaCom = append(gammaCom, iterationCom[:]...)
	}
	p.hGamma = hash(gammaCom)
	p.hOmega = hash(omegaCom)

	return
}

//PreprocessChallenge generates the list of index for closed and open iterations for the preprocessing, given the number of iterations needed for each.
//Used by the verifier
func PreprocessChallenge(nbIterations, nbOpenings int) (openList, closedList []uint32) {
	indexList := make([]uint32, nbIterations)
	for i := 0; i < nbIterations; i++ {
		indexList[i] = uint32(i)
	}
	mr.Seed(time.Now().UnixNano())
	mr.Shuffle(len(indexList), func(i, j int) { indexList[i], indexList[j] = indexList[j], indexList[i] })

	openList = indexList[:nbOpenings]
	closedList = indexList[nbOpenings:]
	return
}

//Prove computes the ZKB++ proof of circuit c, given input input, KKWContext ctx, and the list of open and closed iterations. Returns a ZKBProof and the output of circuit.
func Prove(c *Circuit, input []ZKBVar, ctx *KKWContext, challengesIndex, closedIndex []uint32) (p ZKBProof, output []ZKBVar) {
	nbIterations := len(closedIndex)
	p = ZKBProof{
		//general parameters
		nbIterations: nbIterations,
		c:            c,
		inputSize:    len(input),

		//Circuit evaluation
		e:   make([]int, nbIterations),
		bs:  make([]b, nbIterations),
		zs:  make([]z, nbIterations),
		y:   make([][]*big.Int, nbIterations),
		rqY: make([][]*lr.Poly, nbIterations),
		z2Y: make([][]*big.Int, nbIterations),

		//KKW open part
		omegaCom: make([][sha256.Size]byte, len(challengesIndex)),
		kkwSeeds: make([][]byte, len(challengesIndex)),

		//KKW closed part
		salt:        ctx.salt,
		deltas:      make([][]*big.Int, nbIterations),
		omegaRand:   make([][]byte, nbIterations),
		inputOffset: make([][]*big.Int, nbIterations),
		gammaRand:   make([][]byte, nbIterations),
		seedCom:     make([][sha256.Size]byte, nbIterations),
	}

	//KKW Part for open iterations
	for i, c := range challengesIndex {
		p.omegaCom[i] = ctx.omegaCom[c]
		p.kkwSeeds[i] = ctx.seeds[c]
	}

	//ZKBPP Part (Circuit simulation)

	as := make([]a, p.nbIterations)

	storedViews := make([][3][]*big.Int, p.nbIterations)
	storedRqViews := make([][3][]*lr.Poly, p.nbIterations)
	storedSeeds := make([][3][]byte, p.nbIterations)

	for i, index := range closedIndex {

		//setup circuit
		c.preprocessing = ctx.offsets[index]
		prng, _ := utils.NewKeyedPRNG(ctx.seeds[index])
		c.generateSeeds(prng)
		//evaluate circuit
		output = c.evaluate(input)

		//store view for computing z
		storedViews[i][0] = c.views.player1
		storedViews[i][1] = c.views.player2
		storedViews[i][2] = c.views.player3

		storedRqViews[i][0] = c.rqViews.player1
		storedRqViews[i][1] = c.rqViews.player2
		storedRqViews[i][2] = c.rqViews.player3

		//store seeds for computing z
		storedSeeds[i][0] = c.seeds[0]
		storedSeeds[i][1] = c.seeds[1]
		storedSeeds[i][2] = c.seeds[2]

		//store shares of player3 if needed => not needed anymore, will send offset
		//storedShare2[i] = c.views.input3

		//store output result in y
		p.y[i] = make([]*big.Int, 0)
		p.rqY[i] = make([]*lr.Poly, 0)
		p.z2Y[i] = make([]*big.Int, 0)
		for _, zkvar := range output {
			if zkvar.RqValue != nil {
				p.rqY[i] = append(p.rqY[i], zkvar.RqValue)
			} else if zkvar.Z2Value != nil {
				p.z2Y[i] = append(p.z2Y[i], Copy(zkvar.Z2Value))
			} else {
				p.y[i] = append(p.y[i], Copy(zkvar.Value))
			}
		}

		//store outputShares in a
		var currentA a
		for n := 0; n < 3; n++ {
			shares := make([]*big.Int, 0)
			rqShares := make([]*lr.Poly, 0)
			z2Shares := make([]*big.Int, 0)
			for _, zkvar := range output {
				if zkvar.rqShares != nil {
					rqShares = append(rqShares, zkvar.rqShares[n])
				} else if zkvar.z2Shares != nil {
					z2Shares = append(z2Shares, zkvar.z2Shares[n])
				} else {
					shares = append(shares, zkvar.shares[n])
				}
			}
			currentA.outputShares[n] = shares
			currentA.rqOutputShares[n] = rqShares
			currentA.z2OutputShares[n] = z2Shares
		}

		//store commits in a
		currentA.commits[0] = computeCommit(c.seeds[0], c.views.input1, c.views.player1, c.rqViews.player1)
		currentA.commits[1] = computeCommit(c.seeds[1], c.views.input2, c.views.player2, c.rqViews.player2)
		currentA.commits[2] = computeCommit(c.seeds[2], c.views.input3, c.views.player3, c.rqViews.player3)

		//store current A in as
		as[i] = currentA

		//KKW closed iteration phis and deltas
		p.deltas[i] = ctx.offsets[index].deltas
		p.omegaRand[i] = ctx.omegaRand[index]
		p.inputOffset[i] = ctx.offsets[index].phis
		p.gammaRand[i] = ctx.gammaRand[index]

	}

	//compute e
	p.e = computeChallenge(as, p.nbIterations)
	fmt.Println("Sent challenges are :", p.e)

	for i, index := range closedIndex {

		switch p.e[i] {
		case 0:
			//store b
			p.bs[i].ye2 = as[i].outputShares[2]
			p.bs[i].rqYe2 = as[i].rqOutputShares[2]
			p.bs[i].z2Ye2 = as[i].z2OutputShares[2]
			p.bs[i].ce2 = as[i].commits[2]

			//store z
			p.zs[i].viewe1 = storedViews[i][1]
			p.zs[i].rqViewe1 = storedRqViews[i][1]
			p.zs[i].seeds[0] = storedSeeds[i][0]
			p.zs[i].seeds[1] = storedSeeds[i][1]
			p.zs[i].x3Offset = ctx.offsets[index].phis

			//store seed commit
			p.seedCom[i] = ctx.gammaiCom[index][2]

		case 1:
			//store b
			p.bs[i].ye2 = as[i].outputShares[0]
			p.bs[i].rqYe2 = as[i].rqOutputShares[0]
			p.bs[i].z2Ye2 = as[i].z2OutputShares[0]
			p.bs[i].ce2 = as[i].commits[0]

			//store z
			p.zs[i].viewe1 = storedViews[i][2]
			p.zs[i].rqViewe1 = storedRqViews[i][2]
			p.zs[i].seeds[0] = storedSeeds[i][1]
			p.zs[i].seeds[1] = storedSeeds[i][2]
			p.zs[i].x3Offset = ctx.offsets[index].phis

			//store seed commit
			p.seedCom[i] = ctx.gammaiCom[index][0]

		case 2:
			//store b
			p.bs[i].ye2 = as[i].outputShares[1]
			p.bs[i].rqYe2 = as[i].rqOutputShares[1]
			p.bs[i].z2Ye2 = as[i].z2OutputShares[1]
			p.bs[i].ce2 = as[i].commits[1]

			//store z
			p.zs[i].viewe1 = storedViews[i][0]
			p.zs[i].rqViewe1 = storedRqViews[i][0]
			p.zs[i].seeds[0] = storedSeeds[i][2]
			p.zs[i].seeds[1] = storedSeeds[i][0]
			p.zs[i].x3Offset = ctx.offsets[index].phis

			//store seed commit
			p.seedCom[i] = ctx.gammaiCom[index][1]
		}
	}

	//remove views and seeds and prng from circuit
	p.c.resetAll()

	return
}

//Verify verifies a ZKBProof p and KKWProof kkwP, given open and closed index list. Returns true iff the proof is valid
func Verify(p ZKBProof, kkwP KKWProof, challengesIndex, closedIndex []uint32) bool {
	//circuit setup
	c := p.c

	//commitment for Preprocessing
	omegaCom := make([][]byte, len(closedIndex)+len(challengesIndex))
	gammaCom := make([][]byte, len(closedIndex)+len(challengesIndex))

	//KKW Checks, open iterations
	for i, chall := range challengesIndex {
		iterSeed := p.kkwSeeds[i]
		iterationPrng, _ := utils.NewKeyedPRNG(iterSeed)
		input := make([]ZKBVar, p.inputSize)
		//dummy input for preprocessing, we won't care about input offset
		for j := 0; j < p.inputSize; j++ {
			input[j] = c.VarUint64(0)
		}
		c.preprocess(input, iterationPrng)
		//compute commits for triples
		randomness := make([]byte, SECURITY_LEVEL)
		iterationPrng.Clock(randomness)
		triplesOffsetCom := computeOffsetCommit(c.preprocessing.deltas, randomness, p.salt)

		//compute commits for seeds
		c.rand[0].Clock(randomness)
		seed1Com := computeSeedCommit(c.seeds[0], randomness, p.salt)
		c.rand[1].Clock(randomness)
		seed2Com := computeSeedCommit(c.seeds[1], randomness, p.salt)
		c.rand[2].Clock(randomness)
		seed3Com := computeSeedCommit(c.seeds[2], randomness, p.salt)

		//compute gamma Commitment for this iteration
		iterationCom := hash(triplesOffsetCom[:], seed1Com[:], seed2Com[:], seed3Com[:])
		gammaCom[chall] = iterationCom[:]
		omegaCom[chall] = p.omegaCom[i][:]

	}

	//Circuit checks (closed iterations)
	as := make([]a, p.nbIterations)

	for i, index := range closedIndex {

		//reset circuit
		c.resetAll()

		//random generator setup
		c.seeds[0] = p.zs[i].seeds[0]
		c.seeds[1] = p.zs[i].seeds[1]
		c.rand[0], _ = utils.NewKeyedPRNG(c.seeds[0])
		c.rand[1], _ = utils.NewKeyedPRNG(c.seeds[1])

		//view setup
		c.views.player2 = p.zs[i].viewe1
		c.rqViews.player2 = p.zs[i].rqViewe1

		//deltas setup
		c.preprocessing.deltas = p.deltas[i]
		c.preprocessing.deltasIndex = 0

		//input share setup
		input := make([]ZKBVar, p.inputSize)

		var share0 *big.Int
		var share1 *big.Int

		for j := range input {
			switch p.e[i] {
			case 0:
				share0 = c.generateRandomZqElem(0)
				share1 = c.generateRandomZqElem(1)
			case 1:
				share0 = c.generateRandomZqElem(0)
				share1 = c.Add(c.generateRandomZqElem(1), p.zs[i].x3Offset[j])

			case 2:
				share0 = c.Add(c.generateRandomZqElem(0), p.zs[i].x3Offset[j])
				share1 = c.generateRandomZqElem(1)
			}

			input[j] = ZKBVar{nil, []*big.Int{share0, share1}, nil, nil, nil, nil}
			c.views.input1 = append(c.views.input1, share0)
			c.views.input2 = append(c.views.input2, share1)
		}

		output := c.verify(input, p.e[i])

		//store outputShares in a
		var tmpA a
		for n := 0; n < 2; n++ {
			shares := make([]*big.Int, 0)
			rqShares := make([]*lr.Poly, 0)
			z2Shares := make([]*big.Int, 0)
			for _, zkvar := range output {
				if zkvar.rqShares != nil {
					rqShares = append(rqShares, zkvar.rqShares[n])
				} else if zkvar.z2Shares != nil {
					z2Shares = append(z2Shares, zkvar.z2Shares[n])
				} else {
					shares = append(shares, zkvar.shares[n])
				}
			}

			tmpA.outputShares[n] = shares
			tmpA.rqOutputShares[n] = rqShares
			tmpA.z2OutputShares[n] = z2Shares
		}

		tmpA.outputShares[2] = p.bs[i].ye2
		tmpA.rqOutputShares[2] = p.bs[i].rqYe2
		tmpA.z2OutputShares[2] = p.bs[i].z2Ye2

		//store commits in currentA
		tmpA.commits[0] = computeCommit(c.seeds[0], c.views.input1, c.views.player1, c.rqViews.player1)
		tmpA.commits[1] = computeCommit(c.seeds[1], c.views.input2, c.views.player2, c.rqViews.player2)
		tmpA.commits[2] = p.bs[i].ce2

		//restore indices ordering
		//before 0 = player e, 1 = player e+1, 2 = player e+2
		//after 0 = player 1, 1 = player 2, 2 = player 3
		var currentA a
		switch p.e[i] {
		case 0:
			//nothing to do, already in order
			currentA.outputShares = [3][]*big.Int{tmpA.outputShares[0], tmpA.outputShares[1], tmpA.outputShares[2]}
			currentA.rqOutputShares = [3][]*lr.Poly{tmpA.rqOutputShares[0], tmpA.rqOutputShares[1], tmpA.rqOutputShares[2]}
			currentA.z2OutputShares = [3][]*big.Int{tmpA.z2OutputShares[0], tmpA.z2OutputShares[1], tmpA.z2OutputShares[2]}
			currentA.commits = [3][sha256.Size]byte{tmpA.commits[0], tmpA.commits[1], tmpA.commits[2]}
		case 1:
			currentA.outputShares = [3][]*big.Int{tmpA.outputShares[2], tmpA.outputShares[0], tmpA.outputShares[1]}
			currentA.rqOutputShares = [3][]*lr.Poly{tmpA.rqOutputShares[2], tmpA.rqOutputShares[0], tmpA.rqOutputShares[1]}
			currentA.z2OutputShares = [3][]*big.Int{tmpA.z2OutputShares[2], tmpA.z2OutputShares[0], tmpA.z2OutputShares[1]}
			currentA.commits = [3][sha256.Size]byte{tmpA.commits[2], tmpA.commits[0], tmpA.commits[1]}
		case 2:
			currentA.outputShares = [3][]*big.Int{tmpA.outputShares[1], tmpA.outputShares[2], tmpA.outputShares[0]}
			currentA.rqOutputShares = [3][]*lr.Poly{tmpA.rqOutputShares[1], tmpA.rqOutputShares[2], tmpA.rqOutputShares[0]}
			currentA.z2OutputShares = [3][]*big.Int{tmpA.z2OutputShares[1], tmpA.z2OutputShares[2], tmpA.z2OutputShares[0]}
			currentA.commits = [3][sha256.Size]byte{tmpA.commits[1], tmpA.commits[2], tmpA.commits[0]}
		}

		as[i] = currentA

		//KKW closed iterations check
		randomness := make([]byte, SECURITY_LEVEL)

		//check omegaCom
		inputOffsetCom := computeOffsetCommit(p.inputOffset[i], p.omegaRand[i], p.salt)
		omegaCom[index] = inputOffsetCom[:]

		//check deltas commitment
		triplesOffsetCom := computeOffsetCommit(p.deltas[i], p.gammaRand[i], p.salt)

		//check player seeds commitment
		c.rand[0].Clock(randomness)
		seed1Com := computeSeedCommit(c.seeds[0], randomness, p.salt)
		c.rand[1].Clock(randomness)
		seed2Com := computeSeedCommit(c.seeds[1], randomness, p.salt)
		seed3Com := p.seedCom[i]

		//indices reording for seeds
		var iterationCom [sha256.Size]byte
		switch p.e[i] {
		case 0:
			iterationCom = hash(triplesOffsetCom[:], seed1Com[:], seed2Com[:], seed3Com[:])
		case 1:
			iterationCom = hash(triplesOffsetCom[:], seed3Com[:], seed1Com[:], seed2Com[:])
		case 2:
			iterationCom = hash(triplesOffsetCom[:], seed2Com[:], seed3Com[:], seed1Com[:])

		}
		gammaCom[index] = iterationCom[:]

	}

	//recomputing challenge from proof
	e := computeChallenge(as, p.nbIterations)
	fmt.Println("Recomputed Challenges are", e)

	challengeOK := compare(e, p.e)

	//KKW gamma and omega checks
	hGamma := hash(gammaCom...)
	hOmega := hash(omegaCom...)

	hGammaOK := hGamma == kkwP.hGamma
	hOmegaOK := hOmega == kkwP.hOmega

	fmt.Println("Gamma OK ?:", hGammaOK)
	fmt.Println("Omega OK ?:", hOmegaOK)

	return challengeOK && hGammaOK && hOmegaOK

}

//computeCommit computes the commit to input shares, views and seeds and returns it
func computeCommit(seed []byte, inputShare []*big.Int, view []*big.Int, rqView []*lr.Poly) [sha256.Size]byte {
	data := make([]byte, 0)

	//pack seed into data
	data = append(data, seed...)

	//pack input_share into data
	for _, q := range inputShare {
		data = append(data, q.Bytes()...)
	}

	//pack view into data
	for _, b := range view {
		data = append(data, b.Bytes()...)
	}

	//pack rqView into data
	for _, p := range rqView {
		pBytes, _ := p.MarshalBinary()
		data = append(data, pBytes...)
	}

	return sha256.Sum256(data)
}

//computeOffsetCommit computes the salted commit to input offset and returns it
func computeOffsetCommit(offset []*big.Int, randomness []byte, salt []byte) [sha256.Size]byte {
	data := make([]byte, 0)

	//pack offset into data
	for _, q := range offset {
		data = append(data, q.Bytes()...)
	}
	//pack randomness into data
	data = append(data, randomness...)
	//pack salt into data
	data = append(data, salt...)

	return sha256.Sum256(data)
}

//computeSeedCommit computes the salted commit to the seeds and returns it
func computeSeedCommit(seed, randomness, salt []byte) [sha256.Size]byte {
	data := make([]byte, 0)

	//pack seed into data
	data = append(data, seed...)
	//pack randomness into data
	data = append(data, randomness...)
	//pack salt into data
	data = append(data, salt...)

	return sha256.Sum256(data)
}

//hash concatenates the given slice of bytes and hashes them, returning the result
func hash(slices ...[]byte) [sha256.Size]byte {
	data := make([]byte, 0)

	for _, slice := range slices {
		data = append(data, slice...)
	}
	return sha256.Sum256(data)
}

//computeChallenge computes the challenges index given a and a number of iterations. Returns the challenges index
func computeChallenge(as []a, nbIterations int) (e []int) {
	data := make([]byte, 0)

	for i := 0; i < nbIterations; i++ {

		//pack an a into data

		//pack outputShare into data
		for _, zkbvar := range as[i].outputShares {
			for _, q := range zkbvar {
				data = append(data, q.Bytes()...)
			}
		}
		//pack rqOutputShare into data
		for _, zkbvar := range as[i].rqOutputShares {
			for _, p := range zkbvar {
				pBytes, _ := p.MarshalBinary()
				data = append(data, pBytes...)
			}
		}

		//pack z2OutputShare into data
		for _, zkbvar := range as[i].z2OutputShares {
			for _, b := range zkbvar {
				data = append(data, b.Bytes()...)
			}
		}

		//pack commitment into data
		for _, c := range as[i].commits {
			data = append(data, c[:]...)
		}
	}

	hash := sha256.Sum256(data)

	e = make([]int, nbIterations)

	for i := 0; i < nbIterations; {

		//for each byte in hash
		for j := 0; j < sha256.Size; j++ {
			//extracting at most 4 challenge per bytes
			currentByte := hash[j]
			for k := 0; k < 4 && i < nbIterations; k++ {
				candidateE := currentByte & 3
				if candidateE != 3 {
					e[i] = int(candidateE)
					i++
				}
				currentByte >>= 2
			}
		}
		hash = sha256.Sum256(hash[:])

	}

	return
}

//compare compares two slices of int, returns true iff they are equal
func compare(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
