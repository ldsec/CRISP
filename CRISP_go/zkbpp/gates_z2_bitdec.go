package zkbpp

//This file contains declaration for all bitdec gates for Z2

import (
	"math/big"
)

func mpcBitDec(x []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	binX := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	beta := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	gamma := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	for j := 0; j < c.z2.bitlen; j++ {

		binX[0].SetBit(binX[0], 0, x[0].Bit(j))
		binX[1].SetBit(binX[1], 0, x[1].Bit(j))
		binX[2].SetBit(binX[2], 0, x[2].Bit(j))

		z[0].SetBit(z[0], j, Xor(binX[0], gamma[0], beta[0]).Bit(0))
		z[1].SetBit(z[1], j, Xor(binX[1], gamma[1], beta[1]).Bit(0))
		z[2].SetBit(z[2], j, Xor(binX[2], gamma[2], beta[2]).Bit(0))

		gamma = mpcBitDecMaj3(binX, beta, gamma, c)

		beta = mpcBitDecMaj1(binX, c)
	}

	return
}

func mpcBitDecVerif(x []*big.Int, c *Circuit) (z []*big.Int) {
	z = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	binX := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	beta := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	gamma := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	for j := 0; j < c.z2.bitlen; j++ {

		binX[0].SetBit(binX[0], 0, x[0].Bit(j))
		binX[1].SetBit(binX[1], 0, x[1].Bit(j))

		z[0].SetBit(z[0], j, Xor(binX[0], gamma[0], beta[0]).Bit(0))
		z[1].SetBit(z[1], j, Xor(binX[1], gamma[1], beta[1]).Bit(0))

		gamma = mpcBitDecMaj3(binX, beta, gamma, c)

		beta = mpcBitDecMaj1(binX, c)
	}

	return
}

func mpcBitDecMaj1(x []*big.Int, c *Circuit) (z []*big.Int) {
	x_split := make([][]*big.Int, 3)
	x_split[0] = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	x_split[1] = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	x_split[2] = []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	//Layout for verification should be :
	//e=0 : x0  0  0     e=1 :  0  0 x2     e=2 :  0 x1  0
	//       0 x1  0           x0  0  0            0  0 x2
	//       0  0 x2            0 x1  0           x0  0  0
	//Formula should be as following
	//For x0 : [e][0]
	//For x1 : [(e+1)%3][1]
	//For x2 : [(e+2)%3][2]
	x_split[c.z2Gates.e][0] = x[0]
	x_split[(c.z2Gates.e+1)%3][1] = x[1]
	x_split[(c.z2Gates.e+2)%3][2] = x[2]

	z = mpcBitDecMaj3(x_split[0], x_split[1], x_split[2], c)

	return
}

func mpcBitDecMaj3(w, x, y []*big.Int, c *Circuit) (z []*big.Int) {
	tmp0 := c.z2Gates.xor(w, x, c)
	tmp1 := c.z2Gates.xor(w, y, c)
	tmp2 := c.z2Gates.and(tmp0, tmp1, c)
	z = c.z2Gates.xor(tmp2, w, c)
	return
}

//================================================================
// PREPROCESS GATES
//================================================================
func mpcZ2BitDecPreprocess(x []*big.Int, circ *Circuit) (z []*big.Int) {
	for j := 0; j < circ.z2.bitlen; j++ {
		mpcZ2Preprocess(nil, nil, circ)
		mpcZ2Preprocess(nil, nil, circ)
	}

	return
}
