package zkbpp

//This file contains declaration for all basic gates for Z2

import "math/big"

func mpcZ2Xor(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = Xor(x[0], y[0])
	z[1] = Xor(x[1], y[1])
	z[2] = Xor(x[2], y[2])

	return
}

func mpcZ2XorVerif(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0] = Xor(x[0], y[0])
	z[1] = Xor(x[1], y[1])

	return
}

func mpcZ2Or(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	xn := mpcZ2Not(x, nil, c)
	yn := mpcZ2Not(y, nil, c)
	zn := mpcZ2And(xn, yn, c)
	z = mpcZ2Not(zn, nil, c)
	return
}

func mpcZ2OrVerif(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	xn := mpcZ2NotVerif(x, nil, c)
	yn := mpcZ2NotVerif(y, nil, c)
	zn := mpcZ2AndVerif(xn, yn, c)
	z = mpcZ2NotVerif(zn, nil, c)
	return
}

func mpcZ2Not(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0].Not(x[0])
	z[1].Not(x[1])
	z[2].Not(x[2])

	return
}

func mpcZ2NotVerif(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	z[0].Not(x[0])
	z[1].Not(x[1])

	return
}

func mpcZ2And(x, y []*big.Int, circ *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	a := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1), circ.generateRandomZ2Elem(2)}
	b := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1), circ.generateRandomZ2Elem(2)}
	c := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1), circ.generateRandomZ2Elem(2)}

	c = mpcZ2Xor(c, []*big.Int{circ.preprocessing.deltas[circ.preprocessing.deltasIndex], circ.preprocessing.deltas[circ.preprocessing.deltasIndex], circ.preprocessing.deltas[circ.preprocessing.deltasIndex]}, circ)
	circ.preprocessing.deltasIndex++

	//compute and reconstruct alpha = (x-a), betas = y-b
	alphas := circ.z2Gates.xor(x, a, circ)
	betas := circ.z2Gates.xor(y, b, circ)

	alpha := Xor(alphas[0], alphas[1], alphas[2])
	beta := Xor(betas[0], betas[1], betas[2])

	for i := 0; i < 3; i++ {
		z[i] = new(big.Int)
		tmp := new(big.Int).And(y[i], alpha)
		tmp1 := new(big.Int).And(x[i], beta)
		tmp2 := new(big.Int).And(alpha, beta)
		z[i].Xor(c[i], tmp)
		tmp3 := new(big.Int).Xor(tmp1, tmp2)
		z[i].Xor(z[i], tmp3)
	}

	//THIS IS NOT A BUG. If player x is hidden, we want her alpha and beta to be sent.
	//If x is hidden, the sent view will be x-1, hence this weird indexing
	circ.views.player1 = append(circ.views.player1, Copy(alphas[1]), Copy(betas[1]))
	circ.views.player2 = append(circ.views.player2, Copy(alphas[2]), Copy(betas[2]))
	circ.views.player3 = append(circ.views.player3, Copy(alphas[0]), Copy(betas[0]))

	return
}

func mpcZ2AndVerif(x, y []*big.Int, circ *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	a := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1)}
	b := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1)}
	c := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1)}

	c = mpcZ2XorVerif(c, []*big.Int{circ.preprocessing.deltas[circ.preprocessing.deltasIndex], circ.preprocessing.deltas[circ.preprocessing.deltasIndex]}, circ)
	circ.preprocessing.deltasIndex++

	//compute and reconstruct alpha = (x-a), betas = y-b
	alphas := circ.z2Gates.xor(x, a, circ)
	betas := circ.z2Gates.xor(y, b, circ)
	//get alpha2 and beta2 from views
	alphas[2] = Copy(circ.views.player2[circ.views.currentIndex])
	circ.views.currentIndex++
	betas[2] = Copy(circ.views.player2[circ.views.currentIndex])
	circ.views.currentIndex++

	alpha := Xor(alphas[0], alphas[1], alphas[2])
	beta := Xor(betas[0], betas[1], betas[2])

	for i := 0; i < 2; i++ {
		z[i] = new(big.Int)
		tmp := new(big.Int).And(y[i], alpha)
		tmp1 := new(big.Int).And(x[i], beta)
		tmp2 := new(big.Int).And(alpha, beta)
		z[i].Xor(c[i], tmp)
		tmp3 := new(big.Int).Xor(tmp1, tmp2)
		z[i].Xor(z[i], tmp3)
	}
	circ.views.player1 = append(circ.views.player1, Copy(alphas[1]), Copy(betas[1]))

	return
}

func mpcZ2RightShift(x []*big.Int, i uint, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	z[0].Rsh(x[0], i)
	z[1].Rsh(x[1], i)
	z[2].Rsh(x[2], i)

	return
}

func mpcZ2RightShiftVerif(x []*big.Int, i uint, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	z[0].Rsh(x[0], i)
	z[1].Rsh(x[1], i)
	return
}

func mpcZ2Add(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	carry := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	tmp := mpcZ2And(x, y, c)
	tmp2 := mpcZ2Xor(x, y, c)
	for i := 0; i < c.z2.bitlen; i++ {
		tmp3 := mpcZ2And(carry, tmp2, c)
		t := mpcZ2Or(tmp3, tmp, c)

		carry[0].SetBit(carry[0], i+1, t[0].Bit(i))

		carry[1].SetBit(carry[1], i+1, t[1].Bit(i))

		carry[2].SetBit(carry[2], i+1, t[2].Bit(i))

	}

	z[0] = Xor(x[0], y[0], carry[0])
	z[1] = Xor(x[1], y[1], carry[1])
	z[2] = Xor(x[2], y[2], carry[2])

	return
}

func mpcZ2AddVerif(x, y []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	carry := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	tmp := mpcZ2AndVerif(x, y, c)
	tmp2 := mpcZ2XorVerif(x, y, c)
	for i := 0; i < c.z2.bitlen; i++ {
		tmp3 := mpcZ2AndVerif(carry, tmp2, c)
		t := mpcZ2OrVerif(tmp3, tmp, c)

		carry[0].SetBit(carry[0], i+1, t[0].Bit(i))
		carry[1].SetBit(carry[1], i+1, t[1].Bit(i))
	}

	z[0] = Xor(x[0], y[0], carry[0])
	z[1] = Xor(x[1], y[1], carry[1])

	return
}

func mpcZ2AddK(x, k []*big.Int, c *Circuit) (z []*big.Int) {
	//since k^k^k = k , we can simply call add with the second var being (k,k,k)
	z = mpcZ2Add(x, []*big.Int{k[0], k[0], k[0]}, c)
	return

}

func mpcZ2AddKVerif(x, k []*big.Int, c *Circuit) (z []*big.Int) {
	//since k^k^k = k , we can simply call add with the second var being (k,k,k)
	z = mpcZ2AddVerif(x, []*big.Int{k[0], k[0], k[0]}, c)
	return
}

//================================================================
// PREPROCESS GATES
//================================================================

func mpcZ2NoOpInt(x []*big.Int, k uint, c *Circuit) (z []*big.Int) { return }
func mpcZ2NoOp(x, y []*big.Int, c *Circuit) (z []*big.Int)         { return }

func mpcZ2Preprocess(x []*big.Int, y []*big.Int, circ *Circuit) (z []*big.Int) {
	a_shares := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1), circ.generateRandomZ2Elem(2)}
	b_shares := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1), circ.generateRandomZ2Elem(2)}
	c_shares := []*big.Int{circ.generateRandomZ2Elem(0), circ.generateRandomZ2Elem(1), circ.generateRandomZ2Elem(2)}

	triples := circ.reconstruct(
		[]ZKBVar{{z2Shares: a_shares},
			{z2Shares: b_shares},
			{z2Shares: c_shares}})

	a := triples[0].Z2Value
	b := triples[1].Z2Value
	c := new(big.Int).And(a, b)
	delta := new(big.Int).Xor(c, triples[2].Z2Value)

	circ.preprocessing.deltas = append(circ.preprocessing.deltas, delta)

	return
}

func mpcZ2AddPreprocess(x, y []*big.Int, c *Circuit) (z []*big.Int) {

	mpcZ2Preprocess(nil, nil, c)
	for i := 0; i < c.z2.bitlen; i++ {
		mpcZ2Preprocess(nil, nil, c)
		mpcZ2Preprocess(nil, nil, c)
	}

	return
}
