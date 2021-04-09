//Package zkbpp implement a ZKCE with preprocessing based on
//CHASE, Melissa, et al. Post-quantum zero-knowledge and signatures from symmetric-key primitives.
//BAUM, Carsten et NOF, Ariel. Concretely-efficient zero-knowledge arguments for arithmetic circuits and their application to lattice-based cryptography.
package zkbpp

import (
	"encoding/binary"
	"math/big"

	cr "github.com/ldsec/CRISP-private/ring"
	lr "github.com/ldsec/lattigo/ring"
	"github.com/ldsec/lattigo/utils"
)

//CircuitDescription represents a function acting as a Circuit description
type CircuitDescription func(input []ZKBVar) []ZKBVar

//views is a struct containing the views of a circuit for ring Zq and Z2
type views struct {
	currentIndex int

	input1 []*big.Int
	input2 []*big.Int
	input3 []*big.Int

	player1 []*big.Int
	player2 []*big.Int
	player3 []*big.Int
}

//rqviews is a struct containing the views of a circuit for ring Rq
type rqViews struct {
	currentIndex int

	player1 []*lr.Poly
	player2 []*lr.Poly
	player3 []*lr.Poly
}

//offset is a struct containing the offset for beaver triplets and input shares
type offset struct {
	deltasIndex int

	deltas []*big.Int
	phis   []*big.Int
}

//Circuit is a struct representing a circuit for ZKCE
type Circuit struct {
	Description CircuitDescription

	//rings
	Rq *lr.Ring
	z2 *z2Ring
	*cr.Ring

	//views
	views   views
	rqViews rqViews

	//preprocessing
	preprocessing offset

	//gates
	gates   gates
	rqGates rqgates
	z2Gates z2gates

	//randomness
	seeds [3][]byte
	rand  [3]*utils.KeyedPRNG
}

//NewCircuit instantiates a new circuit with given ring
func NewCircuit(ring *cr.Ring) *Circuit {
	rq, _ := lr.NewRing(1<<DefaultParamsCRISP().LogN(), DefaultParamsCRISP().Qi())
	return &Circuit{
		Ring: ring,
		z2:   &z2Ring{bitlen: new(big.Int).Sub(ring.Q, big.NewInt(1)).BitLen()},
		Rq:   rq,
	}
}

//SetDescription sets the description of circuit c to d
func (c *Circuit) SetDescription(d CircuitDescription) {
	c.Description = d
}

//verifMode sets the gates of circuit c to the verification gates
func (c *Circuit) verifMode(e int) {
	verifGate.e = e
	z2verifGate.e = e
	c.gates = verifGate
	c.z2Gates = z2verifGate
	c.rqGates = rqVerifGate

}

//evalMode sets the gates of circuit c to the evaluation gate
func (c *Circuit) evalMode() {
	c.gates = evalGate
	c.z2Gates = z2evalGate
	c.rqGates = rqEvalGate
}

//preprocessMode sets the gates of circuit c to the preprocessing gates and resets the offset
func (c *Circuit) preprocessMode() {
	c.gates = preprocessGate
	c.z2Gates = z2preprocessGate
	c.rqGates = rqpreprocessGate
	c.preprocessing = offset{
		deltasIndex: 0,
		deltas:      make([]*big.Int, 0),
		phis:        make([]*big.Int, 0),
	}
}

//generateRandomZqElem generates a random Zq number with prng index k
func (c *Circuit) generateRandomZqElem(k int) (out *big.Int) {
	tmp := make([]byte, (c.Q.BitLen()/8)+1)
	c.rand[k].Clock(tmp)
	out = big.NewInt(0)
	out.SetBytes(tmp)
	out = c.Red(out)
	return
}

//generateRandomZ2Elem generates a random Z2 number with prng index k
func (c *Circuit) generateRandomZ2Elem(k int) (out *big.Int) {
	len_b := (c.z2.bitlen / 8) + 1
	if c.z2.bitlen%8 == 0 {
		len_b = c.z2.bitlen / 8
	}
	tmp := make([]byte, len_b)
	c.rand[k].Clock(tmp)
	out = big.NewInt(0)
	out.SetBytes(tmp)
	out = c.z2.Reduce(out)
	return
}

//generateRandomZqElem generates a random Z2 number of 32 bits with prng index k
func (c *Circuit) generateRandomZ32Elem(k int) (out *big.Int) {
	tmp := make([]byte, 4)
	c.rand[k].Clock(tmp)
	out = big.NewInt(0)
	out.SetBytes(tmp)
	return
}

//generateRandomUint32 generates a random uint32 with prng index k
func (c *Circuit) generateRandomUint32(k int) (out uint32) {
	tmp := make([]byte, 4)
	c.rand[k].Clock(tmp)
	out = binary.BigEndian.Uint32(tmp)
	return
}

//generateSeeds generates the seeds and prng for the players, given a main prng
func (c *Circuit) generateSeeds(prngMain *utils.KeyedPRNG) {

	//generate seeds
	c.seeds[0] = make([]byte, SECURITY_LEVEL)
	c.seeds[1] = make([]byte, SECURITY_LEVEL)
	c.seeds[2] = make([]byte, SECURITY_LEVEL)

	prngMain.Clock(c.seeds[0])
	prngMain.Clock(c.seeds[1])
	prngMain.Clock(c.seeds[2])

	//initiate PRNG
	c.rand[0], _ = utils.NewKeyedPRNG(c.seeds[0])
	c.rand[1], _ = utils.NewKeyedPRNG(c.seeds[1])
	c.rand[2], _ = utils.NewKeyedPRNG(c.seeds[2])
}

//generateShares generates the shares for all input ZKBVar and returns the variables
func (c *Circuit) generateShares(input []ZKBVar) (out []ZKBVar) {
	out = make([]ZKBVar, len(input))

	for i := range input {
		out[i].shares = make([]*big.Int, 3)
		share0 := c.generateRandomZqElem(0)
		share1 := c.generateRandomZqElem(1)
		share2 := c.generateRandomZqElem(2)

		//share2 = share2 + offset_phi
		share2 = c.Add(share2, c.preprocessing.phis[i])

		out[i].shares[0] = share0
		out[i].shares[1] = share1
		out[i].shares[2] = share2

		c.views.input1 = append(c.views.input1, share0)
		c.views.input2 = append(c.views.input2, share1)
		c.views.input3 = append(c.views.input3, share2)

	}

	return
}

//preprocessShares generates the input offset for input variables
func (c *Circuit) preprocessShares(input []ZKBVar) {
	for i := range input {
		share0 := c.generateRandomZqElem(0)
		share1 := c.generateRandomZqElem(1)
		share2 := c.generateRandomZqElem(2)

		//offset_phi = input - (share0 + share1 + share2)
		shareTot := c.Add(c.Add(share0, share1), share2)
		phi := c.Sub(input[i].Value, shareTot)
		c.preprocessing.phis = append(c.preprocessing.phis, phi)

	}

}

//reconstruct reconstructs the value for the sharing of result and returns the variables
func (c *Circuit) reconstruct(result []ZKBVar) (output []ZKBVar) {

	output = make([]ZKBVar, len(result))
	for i, r := range result {

		//RqVar
		if r.rqShares != nil {
			tmp := c.Rq.NewPoly()
			output[i].RqValue = c.Rq.NewPoly()
			//result = shares1 + shares2 + shares3
			c.Rq.Add(r.rqShares[0], r.rqShares[1], tmp)
			c.Rq.Add(tmp, r.rqShares[2], output[i].RqValue)

			output[i].rqShares = []*lr.Poly{r.rqShares[0], r.rqShares[1], r.rqShares[2]}

			//Z2Var
		} else if r.z2Shares != nil {

			//result = shares1 XOR shares2 XOR shares3
			output[i].Z2Value = Xor(r.z2Shares[0], r.z2Shares[1], r.z2Shares[2])

			output[i].z2Shares = []*big.Int{r.z2Shares[0], r.z2Shares[1], r.z2Shares[2]}

			//ZqVar
		} else {
			//result = shares1 + shares2 + shares3
			output[i].Value = c.Add(r.shares[0], r.shares[1])
			output[i].Value = c.Add(output[i].Value, r.shares[2])

			output[i].shares = []*big.Int{r.shares[0], r.shares[1], r.shares[2]}

		}
	}

	return
}

//resetViews resets the views of circuit c
func (c *Circuit) resetViews() {

	c.views = views{
		currentIndex: 0,
		player1:      make([]*big.Int, 0),
		player2:      make([]*big.Int, 0),
		player3:      make([]*big.Int, 0),
		input1:       make([]*big.Int, 0),
		input2:       make([]*big.Int, 0),
		input3:       make([]*big.Int, 0),
	}

	c.rqViews = rqViews{
		currentIndex: 0,
		player1:      make([]*lr.Poly, 0),
		player2:      make([]*lr.Poly, 0),
		player3:      make([]*lr.Poly, 0),
	}

}

//resetAll restets the view, seeds prng and offset of circuit c
func (c *Circuit) resetAll() {

	c.resetViews()
	c.seeds = [3][]byte{}
	c.rand = [3]*utils.KeyedPRNG{}
	c.preprocessing = offset{}

}

//Evaluate evaluates a circuit c with given input x and returns the result
func (c *Circuit) evaluate(x []ZKBVar) (output []ZKBVar) {
	c.evalMode()

	c.resetViews()

	//Split shares
	shared_x := c.generateShares(x)

	//circuit run
	result := c.Description(shared_x)

	//reconstruct result
	output = c.reconstruct(result)

	return
}

//verify runs a circuit c with verification gates and returns the results. e is the index of the reconstructed view
func (c *Circuit) verify(input []ZKBVar, e int) (output []ZKBVar) {
	c.verifMode(e)

	//circuit run
	output = c.Description(input)

	return
}

//preprocess runs a circuit c with preprocessing gates, and master prng
func (c *Circuit) preprocess(input []ZKBVar, prng *utils.KeyedPRNG) {
	c.preprocessMode()

	//generating seeds
	c.generateSeeds(prng)

	//preprocess shares
	c.preprocessShares(input)

	//circuit run
	c.Description(input)

}
