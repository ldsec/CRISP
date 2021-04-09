package zkbpp

import (
	"math/big"

	lr "github.com/ldsec/lattigo/ring"
)

//================================================================
//Gate functions at user's disposal
//================================================================

//MpcAdd adds *big.Int x to *big.Int y and returns the result
func (c *Circuit) MpcAdd(x ZKBVar, y ZKBVar) (z ZKBVar) {
	z.shares = c.gates.add(x.shares, y.shares, c)
	return
}

//MpcAddK adds *big.Int x to constant k and returns the result
func (c *Circuit) MpcAddK(x ZKBVar, k *big.Int) (z ZKBVar) {
	z.shares = c.gates.addk(x.shares, []*big.Int{k}, c)
	return
}

//MpcSub subtract *big.Int y from *big.Int x and returns the result
func (c *Circuit) MpcSub(x ZKBVar, y ZKBVar) (z ZKBVar) {
	z.shares = c.gates.sub(x.shares, y.shares, c)
	return
}

//MpcAddK adds *big.Int x to constant k and returns the result
func (c *Circuit) MpcSubK(x ZKBVar, k *big.Int) (z ZKBVar) {
	z.shares = c.gates.subk(x.shares, []*big.Int{k}, c)
	return
}

//MpcMult multiplies *big.Int x to *big.Int y and returns the result
func (c *Circuit) MpcMult(x ZKBVar, y ZKBVar) (z ZKBVar) {
	z.shares = c.gates.mult(x.shares, y.shares, c)
	return
}

//MpcMultK multiplies *big.Int x to constant k and returns the result
func (c *Circuit) MpcMultK(x ZKBVar, k *big.Int) (z ZKBVar) {
	z.shares = c.gates.multk(x.shares, []*big.Int{k}, c)
	return
}

//MpcRqAdd adds poly x to poly y and returns the result
func (c *Circuit) MpcRqAdd(x ZKBVar, y ZKBVar) (z ZKBVar) {
	z.rqShares = c.rqGates.add(x.rqShares, y.rqShares, c)
	return
}

//MpcRqAddK adds poly x to constant k and returns the result
func (c *Circuit) MpcRqAddK(x ZKBVar, k *lr.Poly) (z ZKBVar) {
	z.rqShares = c.rqGates.addk(x.rqShares, []*lr.Poly{k}, c)
	return
}

//MpcRqMultK multiplies poly x to constant k and returns the result
func (c *Circuit) MpcRqMultK(x ZKBVar, k *lr.Poly) (z ZKBVar) {
	z.rqShares = c.rqGates.multk(x.rqShares, []*lr.Poly{k}, c)
	return
}

//MpcZ2Xor computes the xor of var x and y, and returns the result
func (c *Circuit) MpcZ2Xor(x, y ZKBVar) (z ZKBVar) {
	z.z2Shares = c.z2Gates.xor(x.z2Shares, y.z2Shares, c)
	return
}

//MpcZ2Not computes the not of var x and returns the result
func (c *Circuit) MpcZ2Not(x ZKBVar) (z ZKBVar) {
	z.z2Shares = c.z2Gates.not(x.z2Shares, nil, c)
	return
}

//MpcZ2And computes the and of var x and y, and returns the result
func (c *Circuit) MpcZ2And(x, y ZKBVar) (z ZKBVar) {
	z.z2Shares = c.z2Gates.and(x.z2Shares, y.z2Shares, c)
	return
}

//MpcZ2RightShift rightshift var x by i and returns the result
func (c *Circuit) MpcZ2RightShift(x ZKBVar, i uint) (z ZKBVar) {
	z.z2Shares = c.z2Gates.rightShift(x.z2Shares, i, c)
	return
}

//MpcZ2And add var x and y, and returns the result
func (c *Circuit) MpcZ2Add(x, y ZKBVar) (z ZKBVar) {
	z.z2Shares = c.z2Gates.add(x.z2Shares, y.z2Shares, c)
	for i, share := range z.z2Shares {
		z.z2Shares[i] = c.z2.Reduce(share)
	}
	return
}

//MpcZ2And add var x and constant k, and returns the result
func (c *Circuit) MpcZ2AddK(x ZKBVar, k *big.Int) (z ZKBVar) {
	z.z2Shares = c.z2Gates.addk(x.z2Shares, []*big.Int{k}, c)
	for i, share := range z.z2Shares {
		z.z2Shares[i] = c.z2.Reduce(share)
	}
	return
}

//MpcBitdec transforms a additive secrect sharing into a XOR secrect sharing
//Use to go from ring Zq to ring Z2
func (c *Circuit) MpcBitDec(x ZKBVar) (z ZKBVar) {
	z.z2Shares = c.z2Gates.bitDec(x.shares, c)
	return
}
