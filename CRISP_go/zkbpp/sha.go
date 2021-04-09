package zkbpp

import (
	"encoding/binary"
	"math/big"
)

//length in byte of padding and data in a sha block
var byte_length_dp = 56

//sha init value in ZKBVar form
func hA(n int) ZKBVar {
	h := []uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	return ZKBVar{
		z2Shares: []*big.Int{
			new(big.Int).SetInt64(int64(h[n])),
			new(big.Int).SetInt64(int64(h[n])),
			new(big.Int).SetInt64(int64(h[n]))},
	}
}

//sha key value in bigInt form
func k(n int) *big.Int {
	k := []uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}
	return new(big.Int).SetInt64(int64(k[n]))
}

//shaInit value in uint32 form
func hAInt(n int) []uint32 {
	h := []uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	return []uint32{h[n], h[n], h[n]}
}

//sha k value in uint32 form
func kInt(n int) uint32 {
	k := []uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}
	return k[n]
}

//================================================================
//MPC utils function for SHA. Operate on 32 bits big int
//================================================================

func (c *Circuit) mpcZ2RightRotate32(x ZKBVar, i uint) (z ZKBVar) {
	z.z2Shares = c.z2Gates.rightRotate32(x.z2Shares, i, c)
	return
}

func (c *Circuit) mpcZ2MAJ(w, x, y ZKBVar) (z ZKBVar) {

	tmp0 := c.MpcZ2Xor(w, x)
	tmp1 := c.MpcZ2Xor(w, y)
	tmp2 := c.MpcZ2And(tmp0, tmp1)
	z = c.MpcZ2Xor(tmp2, w)

	return
}

func (c *Circuit) mpcZ2CH(w, x, y ZKBVar) (z ZKBVar) {

	// w & (x^y) ^ y
	tmp0 := c.MpcZ2Xor(x, y)
	tmp1 := c.MpcZ2And(w, tmp0)
	z = c.MpcZ2Xor(tmp1, y)

	return
}

func (c *Circuit) mpcZ2Add32(x, y ZKBVar) (z ZKBVar) {
	z.z2Shares = c.z2Gates.add32(x.z2Shares, y.z2Shares, c)
	for i, share := range z.z2Shares {
		z.z2Shares[i] = Reduce32(share)
	}
	return
}

func (c *Circuit) mpcZ2AddK32(x ZKBVar, k *big.Int) (z ZKBVar) {
	z.z2Shares = c.z2Gates.addk32(x.z2Shares, []*big.Int{k}, c)
	for i, share := range z.z2Shares {
		z.z2Shares[i] = Reduce32(share)
	}
	return
}

//================================================================
//End of MPC utils function for SHA
//================================================================

// MpcZ2Sha compute the SHA-256 of X in a mpc manner. Note that the output value has a bitlen of 256, independent of log(Q)
func (circ *Circuit) MpcZ2Sha(x ZKBVar) (z ZKBVar) {

	//check that everything fits in one block. 447 + 1 + 64 = 512
	if circ.z2.bitlen > 447 {
		panic("This sha algorithms works for only 1 block")
	}

	//================================================================
	// PADDING
	//================================================================
	var input [3][64]byte
	for i := range x.z2Shares {

		//padding
		tmp := new(big.Int)

		//first 1 of padding
		tmp.Lsh(x.z2Shares[i], 1)
		tmp.Add(tmp, big.NewInt(1))
		//0's of padding
		tmp.Lsh(tmp, uint(byte_length_dp*8-circ.z2.bitlen-1)) //1 bit shifting was done for the padding, hence -1

		tmp.FillBytes(input[i][:byte_length_dp])
		binary.BigEndian.PutUint64(input[i][byte_length_dp:], uint64(circ.z2.bitlen))

	}
	//============================================================
	// MESSAGE SCHEDULING
	//============================================================
	var w [64]ZKBVar

	//message schedule w_i for i in [0,15]
	for j := 0; j < 16; j++ {
		w[j].z2Shares = make([]*big.Int, len(x.z2Shares))
		for i := range w[j].z2Shares {
			w[j].z2Shares[i] = new(big.Int).SetBytes(input[i][4*j : 4*(j+1)])
		}
	}

	//message schedule w_i for i in [16,63]
	for j := 16; j < 64; j++ {
		w[j].z2Shares = make([]*big.Int, len(x.z2Shares))

		//sigma0 = ROTR(W[j-15], 7) XOR ROTR(W[j-15], 18) XOR SHR(W[j-15], 3)
		tmp1 := circ.mpcZ2RightRotate32(w[j-15], 7)
		tmp2 := circ.mpcZ2RightRotate32(w[j-15], 18)
		tmp3 := circ.MpcZ2RightShift(w[j-15], 3)
		sigma0 := circ.MpcZ2Xor(tmp1, tmp2)
		sigma0 = circ.MpcZ2Xor(sigma0, tmp3)

		//sigma1 = ROTR(W[j-2], 17) XOR ROTR(W[j-2], 19) XOR SHR(W[j-2], 10)
		tmp1 = circ.mpcZ2RightRotate32(w[j-2], 17)
		tmp2 = circ.mpcZ2RightRotate32(w[j-2], 19)
		tmp3 = circ.MpcZ2RightShift(w[j-2], 10)
		sigma1 := circ.MpcZ2Xor(tmp1, tmp2)
		sigma1 = circ.MpcZ2Xor(sigma1, tmp3)

		//W[j] = sigma0 + sigma1 + W[j-7] + W[j-16]
		tmp1 = circ.mpcZ2Add32(sigma0, sigma1)
		tmp2 = circ.mpcZ2Add32(w[j-7], w[j-16])

		w[j] = circ.mpcZ2Add32(tmp1, tmp2)

	}

	//================================================================
	// INIT SHA VALUE
	//================================================================

	a := hA(0)
	b := hA(1)
	c := hA(2)
	d := hA(3)
	e := hA(4)
	f := hA(5)
	g := hA(6)
	h := hA(7)
	t1 := ZKBVar{z2Shares: []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}}
	t2 := ZKBVar{z2Shares: []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}}

	//================================================================
	// COMPRESSION FUNCTION
	//================================================================

	for i := 0; i < 64; i++ {

		//T1 = h + SIGMA1 + Ch(e,f,g) + K(i) + W(i)

		//SIGMA1 = ROTR(e, 6) XOR ROTR(e, 11) XOR ROTR(e, 25)
		tmp1 := circ.mpcZ2RightRotate32(e, 6)
		tmp2 := circ.mpcZ2RightRotate32(e, 11)
		tmp3 := circ.mpcZ2RightRotate32(e, 25)
		sigma1 := circ.MpcZ2Xor(tmp1, tmp2)
		sigma1 = circ.MpcZ2Xor(sigma1, tmp3)

		tmp4 := circ.mpcZ2CH(e, f, g)

		t1 = circ.mpcZ2Add32(h, sigma1)
		t1 = circ.mpcZ2Add32(t1, tmp4)
		t1 = circ.mpcZ2AddK32(t1, k(i))
		t1 = circ.mpcZ2Add32(t1, w[i])
		//END OF T1

		//T2 = SIGMA0 + Maj(a,b,c)
		//SIGMA0 = ROTR(a, 2) XOR ROTR(a, 13) XOR ROTR(a, 22)
		tmp1 = circ.mpcZ2RightRotate32(a, 2)
		tmp2 = circ.mpcZ2RightRotate32(a, 13)
		tmp3 = circ.mpcZ2RightRotate32(a, 22)
		sigma0 := circ.MpcZ2Xor(tmp1, tmp2)
		sigma0 = circ.MpcZ2Xor(sigma0, tmp3)

		tmp4 = circ.mpcZ2MAJ(a, b, c)

		t2 = circ.mpcZ2Add32(sigma0, tmp4)
		//END OF T2

		//SWAPPING

		h = g
		g = f
		f = e
		e = circ.mpcZ2Add32(d, t1)
		d = c
		c = b
		b = a
		a = circ.mpcZ2Add32(t1, t2)

	}

	final_H := [8]ZKBVar{}
	final_H[0] = circ.mpcZ2Add32(a, hA(0))
	final_H[1] = circ.mpcZ2Add32(b, hA(1))
	final_H[2] = circ.mpcZ2Add32(c, hA(2))
	final_H[3] = circ.mpcZ2Add32(d, hA(3))
	final_H[4] = circ.mpcZ2Add32(e, hA(4))
	final_H[5] = circ.mpcZ2Add32(f, hA(5))
	final_H[6] = circ.mpcZ2Add32(g, hA(6))
	final_H[7] = circ.mpcZ2Add32(h, hA(7))

	z.z2Shares = make([]*big.Int, len(x.z2Shares))
	for j := 0; j < len(x.z2Shares); j++ {
		z.z2Shares[j] = big.NewInt(0)
		for i := 0; i < 8; i++ {
			z.z2Shares[j].Lsh(z.z2Shares[j], 32)
			z.z2Shares[j].Or(z.z2Shares[j], final_H[i].z2Shares[j])
		}
	}

	return
}

//================================================================
//MPC utils function for SHAFast. Operate on uint32
//================================================================

func (c *Circuit) mpcZ2RightRotate32Fast(x []uint32, i uint32) (z []uint32) {
	z = c.z2Gates.rightRotate32Fast(x, []uint32{i}, c)
	return
}

func (c *Circuit) mpcZ2MAJFast(w, x, y []uint32) (z []uint32) {

	tmp0 := c.z2Gates.xorFast(w, x, c)
	tmp1 := c.z2Gates.xorFast(w, y, c)
	tmp2 := c.z2Gates.andFast(tmp0, tmp1, c)
	z = c.z2Gates.xorFast(tmp2, w, c)

	return
}

func (c *Circuit) mpcZ2CHFast(w, x, y []uint32) (z []uint32) {

	// w & (x^y) ^ y
	tmp0 := c.z2Gates.xorFast(x, y, c)
	tmp1 := c.z2Gates.andFast(w, tmp0, c)
	z = c.z2Gates.xorFast(tmp1, y, c)

	return
}

func (c *Circuit) mpcZ2AddFast(x, y []uint32) (z []uint32) {
	z = c.z2Gates.addFast(x, y, c)
	return
}

func (c *Circuit) mpcZ2AddKFast(x []uint32, k uint32) (z []uint32) {
	z = c.z2Gates.addkFast(x, []uint32{k}, c)
	return
}

func (c *Circuit) mpcZ2XorFast(x, y []uint32) (z []uint32) {
	z = c.z2Gates.xorFast(x, y, c)
	return
}

func (c *Circuit) mpcZ2RightShiftFast(x []uint32, i uint32) (z []uint32) {
	z = c.z2Gates.rightShiftFast(x, []uint32{i}, c)
	return
}

//================================================================
//End of MPC utils function for SHA
//================================================================

// MpcZ2ShaFast compute the SHA-256 of X in a mpc manner, using uint32 for shorter runtime. Note that the output value has a bitlen of 256, independent of log(Q)
func (circ *Circuit) MpcZ2ShaFast(x ZKBVar) (z ZKBVar) {

	//check that everything fits in one block. 447 + 1 + 64 = 512
	if circ.z2.bitlen > 447 {
		panic("This sha algorithms works for only 1 block")
	}

	n := len(x.z2Shares)

	//================================================================
	// PADDING
	//================================================================
	var input [3][64]byte
	for i := range x.z2Shares {

		//padding
		tmp := new(big.Int)

		//first 1 of padding
		tmp.Lsh(x.z2Shares[i], 1)
		tmp.Add(tmp, big.NewInt(1))
		//0's of padding
		tmp.Lsh(tmp, uint(byte_length_dp*8-circ.z2.bitlen-1)) //1 bit shifting was done for the padding, hence -1

		tmp.FillBytes(input[i][:byte_length_dp])
		binary.BigEndian.PutUint64(input[i][byte_length_dp:], uint64(circ.z2.bitlen))

	}
	//============================================================
	// MESSAGE SCHEDULING
	//============================================================
	var w [64][]uint32

	//message schedule w_i for i in [0,15]
	for j := 0; j < 16; j++ {
		w[j] = make([]uint32, n)
		for i := 0; i < n; i++ {
			w[j][i] = binary.BigEndian.Uint32(input[i][4*j : 4*(j+1)])
		}
	}

	//message schedule w_i for i in [16,63]
	for j := 16; j < 64; j++ {

		//sigma0 = ROTR(W[j-15], 7) XOR ROTR(W[j-15], 18) XOR SHR(W[j-15], 3)
		tmp1 := circ.mpcZ2RightRotate32Fast(w[j-15], 7)
		tmp2 := circ.mpcZ2RightRotate32Fast(w[j-15], 18)
		tmp3 := circ.mpcZ2RightShiftFast(w[j-15], 3)
		sigma0 := circ.mpcZ2XorFast(tmp1, tmp2)
		sigma0 = circ.mpcZ2XorFast(sigma0, tmp3)

		//sigma1 = ROTR(W[j-2], 17) XOR ROTR(W[j-2], 19) XOR SHR(W[j-2], 10)
		tmp1 = circ.mpcZ2RightRotate32Fast(w[j-2], 17)
		tmp2 = circ.mpcZ2RightRotate32Fast(w[j-2], 19)
		tmp3 = circ.mpcZ2RightShiftFast(w[j-2], 10)
		sigma1 := circ.mpcZ2XorFast(tmp1, tmp2)
		sigma1 = circ.mpcZ2XorFast(sigma1, tmp3)

		//W[j] = sigma0 + sigma1 + W[j-7] + W[j-16]
		tmp1 = circ.mpcZ2AddFast(sigma0, sigma1)
		tmp2 = circ.mpcZ2AddFast(w[j-7], w[j-16])

		w[j] = circ.mpcZ2AddFast(tmp1, tmp2)

	}

	//================================================================
	// INIT SHA VALUE
	//================================================================

	a := hAInt(0)
	b := hAInt(1)
	c := hAInt(2)
	d := hAInt(3)
	e := hAInt(4)
	f := hAInt(5)
	g := hAInt(6)
	h := hAInt(7)
	var t1, t2 []uint32

	//================================================================
	// COMPRESSION FUNCTION
	//================================================================

	for i := 0; i < 64; i++ {

		//T1 = h + SIGMA1 + Ch(e,f,g) + K(i) + W(i)

		//SIGMA1 = ROTR(e, 6) XOR ROTR(e, 11) XOR ROTR(e, 25)
		tmp1 := circ.mpcZ2RightRotate32Fast(e, 6)
		tmp2 := circ.mpcZ2RightRotate32Fast(e, 11)
		tmp3 := circ.mpcZ2RightRotate32Fast(e, 25)
		sigma1 := circ.mpcZ2XorFast(tmp1, tmp2)
		sigma1 = circ.mpcZ2XorFast(sigma1, tmp3)

		tmp4 := circ.mpcZ2CHFast(e, f, g)

		t1 = circ.mpcZ2AddFast(h, sigma1)
		t1 = circ.mpcZ2AddFast(t1, tmp4)
		t1 = circ.mpcZ2AddKFast(t1, kInt(i))
		t1 = circ.mpcZ2AddFast(t1, w[i])
		//END OF T1

		//T2 = SIGMA0 + Maj(a,b,c)
		//SIGMA0 = ROTR(a, 2) XOR ROTR(a, 13) XOR ROTR(a, 22)
		tmp1 = circ.mpcZ2RightRotate32Fast(a, 2)
		tmp2 = circ.mpcZ2RightRotate32Fast(a, 13)
		tmp3 = circ.mpcZ2RightRotate32Fast(a, 22)
		sigma0 := circ.mpcZ2XorFast(tmp1, tmp2)
		sigma0 = circ.mpcZ2XorFast(sigma0, tmp3)

		tmp4 = circ.mpcZ2MAJFast(a, b, c)

		t2 = circ.mpcZ2AddFast(sigma0, tmp4)
		//END OF T2

		//SWAPPING

		h = g
		g = f
		f = e
		e = circ.mpcZ2AddFast(d, t1)
		d = c
		c = b
		b = a
		a = circ.mpcZ2AddFast(t1, t2)

	}

	var final_H [8][]uint32
	final_H[0] = circ.mpcZ2AddFast(a, hAInt(0))
	final_H[1] = circ.mpcZ2AddFast(b, hAInt(1))
	final_H[2] = circ.mpcZ2AddFast(c, hAInt(2))
	final_H[3] = circ.mpcZ2AddFast(d, hAInt(3))
	final_H[4] = circ.mpcZ2AddFast(e, hAInt(4))
	final_H[5] = circ.mpcZ2AddFast(f, hAInt(5))
	final_H[6] = circ.mpcZ2AddFast(g, hAInt(6))
	final_H[7] = circ.mpcZ2AddFast(h, hAInt(7))

	z.z2Shares = make([]*big.Int, len(x.z2Shares))
	for j := 0; j < len(x.z2Shares); j++ {
		z.z2Shares[j] = big.NewInt(0)
		for i := 0; i < 8; i++ {
			z.z2Shares[j].Lsh(z.z2Shares[j], 32)
			z.z2Shares[j].Or(z.z2Shares[j], big.NewInt(int64(final_H[i][j])))
		}
	}

	return
}

//================================================================
// Non MPC SHA, for reference, checked against actual SHA
//================================================================

func rotr(x uint32, n int) uint32 {
	return x>>n | x<<(32-n)
}

//Sha computes the sha of big.Int x
func (circ *Circuit) Sha(x *big.Int) (z *big.Int) {

	//check that everything fits in one block. 447 + 1 + 64 = 512
	if circ.z2.bitlen > 447 {
		panic("This sha algorithms works for only 1 block")
	}

	//================================================================
	// PADDING
	//================================================================
	var input [64]byte

	//padding
	tmp := new(big.Int)

	//first 1 of padding
	tmp.Lsh(x, 1)
	tmp.Add(tmp, big.NewInt(1))
	//0's of padding
	tmp.Lsh(tmp, uint(byte_length_dp*8-circ.z2.bitlen-1)) //1 bit shifting was done for the padding, hence -1

	tmp.FillBytes(input[:byte_length_dp])
	binary.BigEndian.PutUint64(input[byte_length_dp:], uint64(circ.z2.bitlen))

	//============================================================
	// MESSAGE SCHEDULING
	//============================================================
	var w [64]uint32

	//message schedule w_i for i in [0,15]
	for j := 0; j < 16; j++ {
		w[j] = binary.BigEndian.Uint32(input[4*j : 4*(j+1)])
	}

	//message schedule w_i for i in [16,63]
	for j := 16; j < 64; j++ {

		//sigma0 = ROTR(W[j-15], 7) XOR ROTR(W[j-15], 18) XOR SHR(W[j-15], 3)
		tmp1 := rotr(w[j-15], 7)
		tmp2 := rotr(w[j-15], 18)
		tmp3 := w[j-15] >> 3
		sigma0 := tmp1 ^ tmp2 ^ tmp3

		//sigma1 = ROTR(W[j-2], 17) XOR ROTR(W[j-2], 19) XOR SHR(W[j-2], 10)
		tmp1 = rotr(w[j-2], 17)
		tmp2 = rotr(w[j-2], 19)
		tmp3 = w[j-2] >> 10
		sigma1 := tmp1 ^ tmp2 ^ tmp3

		//W[j] = sigma0 + sigma1 + W[j-7] + W[j-16]
		w[j] = sigma0 + sigma1 + w[j-7] + w[j-16]

	}

	//================================================================
	// INIT SHA VALUE
	//================================================================

	hA := []uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	k := []uint32{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

	a := hA[0]
	b := hA[1]
	c := hA[2]
	d := hA[3]
	e := hA[4]
	f := hA[5]
	g := hA[6]
	h := hA[7]

	//================================================================
	// COMPRESSION FUNCTION
	//================================================================

	for i := 0; i < 64; i++ {

		//T1 = h + SIGMA1 + Ch(e,f,g) + K(i) + W(i)

		//SIGMA1 = ROTR(e, 6) XOR ROTR(e, 11) XOR ROTR(e, 25)
		tmp1 := rotr(e, 6)
		tmp2 := rotr(e, 11)
		tmp3 := rotr(e, 25)
		sigma1 := tmp1 ^ tmp2 ^ tmp3

		//CH
		tmp4 := (e & f) ^ (^e & g)

		t1 := h + sigma1 + tmp4 + k[i] + w[i]
		//END OF T1

		//T2 = SIGMA0 + Maj(a,b,c)
		//SIGMA0 = ROTR(a, 2) XOR ROTR(a, 13) XOR ROTR(a, 22)
		tmp1 = rotr(a, 2)
		tmp2 = rotr(a, 13)
		tmp3 = rotr(a, 22)
		sigma0 := tmp1 ^ tmp2 ^ tmp3

		tmp4 = (a & b) ^ (a & c) ^ (b & c)
		t2 := sigma0 + tmp4
		//END OF T2

		//SWAPPING

		h = g
		g = f
		f = e
		e = d + t1
		d = c
		c = b
		b = a
		a = t1 + t2

	}

	final_H := [8]uint32{}
	final_H[0] = a + hA[0]
	final_H[1] = b + hA[1]
	final_H[2] = c + hA[2]
	final_H[3] = d + hA[3]
	final_H[4] = e + hA[4]
	final_H[5] = f + hA[5]
	final_H[6] = g + hA[6]
	final_H[7] = h + hA[7]

	z = big.NewInt(0)
	for i := 0; i < 8; i++ {
		z.Lsh(z, 32)
		z.Or(z, big.NewInt(int64(final_H[i])))
	}

	return
}
