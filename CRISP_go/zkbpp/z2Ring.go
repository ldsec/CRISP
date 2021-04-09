package zkbpp

import (
	"math/big"
)

//z2Ring is a struct representing a ring over z2, with bitlen bits
type z2Ring struct {
	bitlen int
}

//Copy copies a bigInt and returns it
func Copy(src *big.Int) (dst *big.Int) {
	dst = new(big.Int)
	dst.Set(src)
	return

}

//RightRotate32 rotates a bigInt x for n positions, wrapping after 32 bits
//meant to operate on SHA word, i.e 32 bits. Will fail for other big int
func RightRotate32(x *big.Int, n uint) (z *big.Int) {
	z = new(big.Int).Rsh(x, n)
	tmp := new(big.Int).Lsh(x, 32-n)
	modulo := new(big.Int).Lsh(big.NewInt(1), 32)
	tmp.Mod(tmp, modulo)
	z.Or(z, tmp)
	return
}

//Reduce32 reduces a big.Int modulo 2^32, i.e. on 32 bits
func Reduce32(x *big.Int) (z *big.Int) {
	z = new(big.Int)
	modulo := new(big.Int).Lsh(big.NewInt(1), 32)
	z.Mod(x, modulo)
	return
}

//Xor xors all given arguments and returns the results
func Xor(xs ...*big.Int) (z *big.Int) {
	z = big.NewInt(0)

	for _, v := range xs {
		z.Xor(z, v)
	}
	return
}

//Reduce reduces a big.Int x in the given z2 ring
func (z2 *z2Ring) Reduce(x *big.Int) (z *big.Int) {
	z = new(big.Int)
	modulo := new(big.Int).Lsh(big.NewInt(1), uint(z2.bitlen))
	z.Mod(x, modulo)
	return
}
