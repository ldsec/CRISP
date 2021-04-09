package zkbpp

import (
	"math/big"
)

type gate func([]*big.Int, []*big.Int, *Circuit) []*big.Int

type gates struct {
	add   gate
	addk  gate
	sub   gate
	subk  gate
	mult  gate
	multk gate
	e     int
}

var evalGate = gates{
	mpcAdd,
	mpcAddK,
	mpcSub,
	mpcSubk,
	mpcMult,
	mpcMultK,
	0,
}

var verifGate = gates{
	mpcAddVerif,
	mpcAddKVerif,
	mpcSubVerif,
	mpcSubkVerif,
	mpcMultVerif,
	mpcMultKVerif,
	0,
}

var preprocessGate = gates{
	mpcNoOP,
	mpcNoOP,
	mpcNoOP,
	mpcNoOP,
	mpcMultPreprocess,
	mpcNoOP,
	0,
}

//================================================================
//Eval gates
//================================================================

func mpcAdd(x []*big.Int, y []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = c.Add(x[0], y[0])
	z[1] = c.Add(x[1], y[1])
	z[2] = c.Add(x[2], y[2])

	return
}

func mpcAddK(x []*big.Int, k []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = x[0]
	z[1] = x[1]
	z[2] = x[2]

	z[c.gates.e] = c.Add(x[c.gates.e], k[0])

	return
}

func mpcSub(x []*big.Int, y []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = c.Sub(x[0], y[0])
	z[1] = c.Sub(x[1], y[1])
	z[2] = c.Sub(x[2], y[2])

	return
}

func mpcSubk(x []*big.Int, k []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = x[0]
	z[1] = x[1]
	z[2] = x[2]

	z[c.gates.e] = c.Sub(x[c.gates.e], k[0])

	return
}

func mpcMult(x []*big.Int, y []*big.Int, circ *Circuit) (z []*big.Int) {

	//beaver triples generations
	a := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1), circ.generateRandomZqElem(2)}
	b := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1), circ.generateRandomZqElem(2)}
	c := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1), circ.generateRandomZqElem(2)}

	c = circ.gates.addk(c, []*big.Int{circ.preprocessing.deltas[circ.preprocessing.deltasIndex]}, circ)
	circ.preprocessing.deltasIndex++

	//(x-a) and y-b
	alphas := circ.gates.sub(x, a, circ)
	betas := circ.gates.sub(y, b, circ)

	alpha := circ.Add(circ.Add(alphas[0], alphas[1]), alphas[2])
	beta := circ.Add(circ.Add(betas[0], betas[1]), betas[2])

	//final computation

	tmp := circ.gates.multk(y, []*big.Int{alpha}, circ)
	tmp1 := circ.gates.multk(x, []*big.Int{beta}, circ)
	z = circ.gates.add(c, circ.gates.add(tmp, tmp1, circ), circ)

	tmp2 := circ.Mult(alpha, beta)
	z = circ.gates.subk(z, []*big.Int{tmp2}, circ)

	//THIS IS NOT A BUG. If player x is hidden, we want her alpha and beta to be sent.
	//If x is hidden, the sent view will be x-1, hence this weird indexing
	circ.views.player1 = append(circ.views.player1, Copy(alphas[1]), Copy(betas[1]))
	circ.views.player2 = append(circ.views.player2, Copy(alphas[2]), Copy(betas[2]))
	circ.views.player3 = append(circ.views.player3, Copy(alphas[0]), Copy(betas[0]))

	return
}

//Multiply x by a constant K. len(x) should be 3, len(k) should be 1
func mpcMultK(x []*big.Int, k []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	z[0] = c.Mult(x[0], k[0])
	z[1] = c.Mult(x[1], k[0])
	z[2] = c.Mult(x[2], k[0])

	return
}

//================================================================
//Verif gates
//================================================================
func mpcAddVerif(x []*big.Int, y []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = c.Add(x[0], y[0])
	z[1] = c.Add(x[1], y[1])

	return
}

func mpcAddKVerif(x []*big.Int, k []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = x[0]
	z[1] = x[1]

	//need to compute if view0 is reconstructed
	if c.gates.e == 0 {
		z[0] = c.Add(x[0], k[0])
	}

	//view0 has been sent, we need to add k to it
	if c.gates.e == 2 {
		z[1] = c.Add(x[1], k[0])
	}

	return
}

func mpcSubVerif(x []*big.Int, y []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = c.Sub(x[0], y[0])
	z[1] = c.Sub(x[1], y[1])

	return
}

func mpcSubkVerif(x []*big.Int, k []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = x[0]
	z[1] = x[1]

	//need to compute if view0 is reconstructed
	if c.gates.e == 0 {
		z[0] = c.Sub(x[0], k[0])
	}

	//view0 has been sent, we need to sub k to it
	if c.gates.e == 2 {
		z[1] = c.Sub(x[1], k[0])
	}

	return
}

func mpcMultVerif(x []*big.Int, y []*big.Int, circ *Circuit) (z []*big.Int) {

	a := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1)}
	b := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1)}
	c := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1)}

	//add offset
	c = circ.gates.addk(c, []*big.Int{circ.preprocessing.deltas[circ.preprocessing.deltasIndex]}, circ)
	circ.preprocessing.deltasIndex++

	//construct alphas and betas
	alphas := circ.gates.sub(x, a, circ)
	betas := circ.gates.sub(y, b, circ)

	//get alpha2 and beta2 from views
	alphas[2] = Copy(circ.views.player2[circ.views.currentIndex])
	circ.views.currentIndex++
	betas[2] = Copy(circ.views.player2[circ.views.currentIndex])
	circ.views.currentIndex++

	alpha := circ.Add(circ.Add(alphas[0], alphas[1]), alphas[2])
	beta := circ.Add(circ.Add(betas[0], betas[1]), betas[2])

	//final computation
	tmp := circ.gates.multk(y, []*big.Int{alpha}, circ)
	tmp1 := circ.gates.multk(x, []*big.Int{beta}, circ)
	z = circ.gates.add(c, circ.gates.add(tmp, tmp1, circ), circ)

	tmp2 := circ.Mult(alpha, beta)

	z = circ.gates.subk(z, []*big.Int{tmp2}, circ)

	//reconstruct view for player 0
	circ.views.player1 = append(circ.views.player1, Copy(alphas[1]), Copy(betas[1]))

	return
}

func mpcMultKVerif(x []*big.Int, k []*big.Int, c *Circuit) (z []*big.Int) {

	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = c.Mult(x[0], k[0])
	z[1] = c.Mult(x[1], k[0])

	return
}

//================================================================
//preprocessing gates
//================================================================

//For the local gates, there is nothing to do in preprocessing
func mpcNoOP(x []*big.Int, y []*big.Int, c *Circuit) (z []*big.Int) {
	return
}

func mpcMultPreprocess(x []*big.Int, y []*big.Int, circ *Circuit) (z []*big.Int) {
	a_shares := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1), circ.generateRandomZqElem(2)}
	b_shares := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1), circ.generateRandomZqElem(2)}
	c_shares := []*big.Int{circ.generateRandomZqElem(0), circ.generateRandomZqElem(1), circ.generateRandomZqElem(2)}

	triples := circ.reconstruct(
		[]ZKBVar{{shares: a_shares},
			{shares: b_shares},
			{shares: c_shares}})

	a := triples[0].Value
	b := triples[1].Value
	c := circ.Mult(a, b)
	delta := circ.Sub(c, triples[2].Value)
	circ.preprocessing.deltas = append(circ.preprocessing.deltas, delta)

	return
}
