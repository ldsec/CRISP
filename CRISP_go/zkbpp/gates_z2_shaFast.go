package zkbpp

//This file contains declaration for all fast sha gates for Z2

import "math/big"

//================================================================
// UTILS
//================================================================

func bit(x uint32, i int) uint32 {
	return x >> i & 1
}

func setBit(x uint32, i int, b uint32) uint32 {
	if b == 1 {
		return x | (b << i)
	}
	return x & ^(1 << i)
}

//================================================================
// Fast gates on uint32
//================================================================
func mpcZ2XorFast(x, y []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}

	z[0] = x[0] ^ y[0]
	z[1] = x[1] ^ y[1]
	z[2] = x[2] ^ y[2]

	return
}

func mpcZ2XorFastVerif(x, y []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}

	z[0] = x[0] ^ y[0]
	z[1] = x[1] ^ y[1]

	return
}

func mpcZ2OrFast(x, y []uint32, c *Circuit) (z []uint32) {
	w := []uint32{^x[0], ^x[1], ^x[2]}
	v := []uint32{^y[0], ^y[1], ^y[2]}
	z = mpcZ2AndFast(w, v, c)
	z[0] = ^z[0]
	z[1] = ^z[1]
	z[2] = ^z[2]

	return
}

func mpcZ2OrFastVerif(x, y []uint32, c *Circuit) (z []uint32) {
	w := []uint32{^x[0], ^x[1], 0}
	v := []uint32{^y[0], ^y[1], 0}
	z = mpcZ2AndFastVerif(w, v, c)
	z[0] = ^z[0]
	z[1] = ^z[1]

	return
}

func mpcZ2AndFast(x, y []uint32, circ *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}

	a := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1), circ.generateRandomUint32(2)}
	b := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1), circ.generateRandomUint32(2)}
	c := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1), circ.generateRandomUint32(2)}

	delta := uint32(circ.preprocessing.deltas[circ.preprocessing.deltasIndex].Uint64())
	c = mpcZ2XorFast(c, []uint32{delta, delta, delta}, circ)

	circ.preprocessing.deltasIndex++

	//compute and reconstruct alpha = (x-a), betas = y-b
	alphas := mpcZ2XorFast(x, a, circ)
	betas := mpcZ2XorFast(y, b, circ)

	alpha := alphas[0] ^ alphas[1] ^ alphas[2]
	beta := betas[0] ^ betas[1] ^ betas[2]

	for i := 0; i < 3; i++ {
		tmp := y[i] & alpha
		tmp1 := x[i] & beta
		tmp2 := alpha & beta
		z[i] = c[i] ^ tmp
		tmp3 := tmp1 ^ tmp2
		z[i] = z[i] ^ tmp3
	}

	circ.views.player1 = append(circ.views.player1, big.NewInt(int64(alphas[1])), big.NewInt(int64(betas[1])))
	circ.views.player2 = append(circ.views.player2, big.NewInt(int64(alphas[2])), big.NewInt(int64(betas[2])))
	circ.views.player3 = append(circ.views.player3, big.NewInt(int64(alphas[0])), big.NewInt(int64(betas[0])))

	return
}

func mpcZ2AndFastVerif(x, y []uint32, circ *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}

	a := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1)}
	b := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1)}
	c := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1)}

	delta := uint32(circ.preprocessing.deltas[circ.preprocessing.deltasIndex].Uint64())
	c = mpcZ2XorFastVerif(c, []uint32{delta, delta, delta}, circ)
	circ.preprocessing.deltasIndex++

	//compute and reconstruct alpha = (x-a), betas = y-b
	alphas := mpcZ2XorFastVerif(x, a, circ)
	betas := mpcZ2XorFastVerif(y, b, circ)

	alphas[2] = uint32(circ.views.player2[circ.views.currentIndex].Uint64())
	circ.views.currentIndex++
	betas[2] = uint32(circ.views.player2[circ.views.currentIndex].Uint64())
	circ.views.currentIndex++

	alpha := alphas[0] ^ alphas[1] ^ alphas[2]
	beta := betas[0] ^ betas[1] ^ betas[2]

	for i := 0; i < 2; i++ {
		tmp := y[i] & alpha
		tmp1 := x[i] & beta
		tmp2 := alpha & beta
		z[i] = c[i] ^ tmp
		tmp3 := tmp1 ^ tmp2
		z[i] = z[i] ^ tmp3
	}

	circ.views.player1 = append(circ.views.player1, big.NewInt(int64(alphas[1])), big.NewInt(int64(betas[1])))
	return
}

func mpcZ2RightShiftFast(x []uint32, i []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}
	z[0] = x[0] >> i[0]
	z[1] = x[1] >> i[0]
	z[2] = x[2] >> i[0]

	return
}

func mpcZ2RightShiftFastVerif(x []uint32, i []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}
	z[0] = x[0] >> i[0]
	z[1] = x[1] >> i[0]
	return
}

func mpcZ2RightRotate32Fast(x []uint32, i []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}
	z[0] = x[0]>>i[0] | x[0]<<(32-i[0])
	z[1] = x[1]>>i[0] | x[1]<<(32-i[0])
	z[2] = x[2]>>i[0] | x[2]<<(32-i[0])
	return
}

func mpcZ2RightRotate32FastVerif(x []uint32, i []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}
	z[0] = x[0]>>i[0] | x[0]<<(32-i[0])
	z[1] = x[1]>>i[0] | x[1]<<(32-i[0])
	return
}

func mpcZ2AddFast(x, y []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}

	carry := []uint32{0, 0, 0}

	tmp := mpcZ2AndFast(x, y, c)
	tmp2 := mpcZ2XorFast(x, y, c)
	for i := 0; i < 31; i++ {
		tmp3 := mpcZ2AndFast(carry, tmp2, c)
		t := mpcZ2OrFast(tmp3, tmp, c)

		carry[0] = setBit(carry[0], i+1, bit(t[0], i))
		carry[1] = setBit(carry[1], i+1, bit(t[1], i))
		carry[2] = setBit(carry[2], i+1, bit(t[2], i))
	}

	z[0] = x[0] ^ y[0] ^ carry[0]
	z[1] = x[1] ^ y[1] ^ carry[1]
	z[2] = x[2] ^ y[2] ^ carry[2]
	return
}

func mpcZ2AddFastVerif(x, y []uint32, c *Circuit) (z []uint32) {
	z = []uint32{0, 0, 0}

	carry := []uint32{0, 0, 0}

	tmp := mpcZ2AndFastVerif(x, y, c)
	tmp2 := mpcZ2XorFastVerif(x, y, c)
	for i := 0; i < 31; i++ {
		tmp3 := mpcZ2AndFastVerif(carry, tmp2, c)
		t := mpcZ2OrFastVerif(tmp3, tmp, c)

		carry[0] = setBit(carry[0], i+1, bit(t[0], i))
		carry[1] = setBit(carry[1], i+1, bit(t[1], i))
	}
	z[0] = x[0] ^ y[0] ^ carry[0]
	z[1] = x[1] ^ y[1] ^ carry[1]

	return
}

func mpcZ2AddKFast(x, k []uint32, c *Circuit) (z []uint32) {
	//since k^k^k = k , we can simply call add with the second var being (k,k,k)
	z = mpcZ2AddFast(x, []uint32{k[0], k[0], k[0]}, c)
	return

}

func mpcZ2AddKFastVerif(x, k []uint32, c *Circuit) (z []uint32) {
	//since k^k^k = k , we can simply call add with the second var being (k,k,k)
	z = mpcZ2AddFastVerif(x, []uint32{k[0], k[0], k[0]}, c)
	return
}

//================================================================
// PREPROCESS GATES
//================================================================

func mpcZ2NoOpFast(x, y []uint32, c *Circuit) (z []uint32) { return }

func mpcZ2PreprocessFast(x []uint32, y []uint32, circ *Circuit) (z []uint32) {
	a_shares := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1), circ.generateRandomUint32(2)}
	b_shares := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1), circ.generateRandomUint32(2)}
	c_shares := []uint32{circ.generateRandomUint32(0), circ.generateRandomUint32(1), circ.generateRandomUint32(2)}

	a := a_shares[0] ^ a_shares[1] ^ a_shares[2]
	b := b_shares[0] ^ b_shares[1] ^ b_shares[2]
	c := a & b
	delta := c ^ (c_shares[0] ^ c_shares[1] ^ c_shares[2])

	circ.preprocessing.deltas = append(circ.preprocessing.deltas, big.NewInt(int64(delta)))

	return
}

func mpcZ2AddPreprocessFast(x, y []uint32, c *Circuit) (z []uint32) {
	mpcZ2PreprocessFast(nil, nil, c)
	for i := 0; i < 31; i++ {
		mpcZ2PreprocessFast(nil, nil, c)
		mpcZ2PreprocessFast(nil, nil, c)
	}

	return
}
