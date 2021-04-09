package zkbpp

import (
	"math/big"

	lr "github.com/ldsec/lattigo/ring"
)

//ZKBVar is a struct to represent an input variable to a Circuit.
type ZKBVar struct {
	//Zq elems
	Value  *big.Int
	shares []*big.Int

	//Z2 elems
	Z2Value  *big.Int
	z2Shares []*big.Int

	//Rq elems
	RqValue  *lr.Poly
	rqShares []*lr.Poly
}

//VarUint64 returns a new var with value x, in ring Zq
func (c *Circuit) VarUint64(x uint64) ZKBVar {
	return ZKBVar{big.NewInt(0).SetUint64(x), []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}, nil, nil, nil, nil}
}

//Var returns a new var with value x, in ring Zq
func (c *Circuit) Var(x *big.Int) ZKBVar {
	return ZKBVar{Copy(x), []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}, nil, nil, nil, nil}
}

//Z2Var returns a new var with value value, in ring Z2
func (c *Circuit) Z2Var(value string) ZKBVar {
	x, _ := new(big.Int).SetString(value, 2)
	return ZKBVar{nil, nil, x, []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}, nil, nil}
}

//RqVar returns a new var with coefficients coeffs, in ring Rq
func (c *Circuit) RqVar(coeffs []uint64) ZKBVar {
	poly := c.Rq.NewPoly()
	c.Rq.SetCoefficientsUint64(coeffs, poly)
	return ZKBVar{nil, nil, nil, nil, poly, []*lr.Poly{c.Rq.NewPoly(), c.Rq.NewPoly(), c.Rq.NewPoly()}}
}

//VarFromPoly transforms a poly into an array of ZKBVar with value in Zq
func (c *Circuit) VarFromPoly(x *lr.Poly) []ZKBVar {
	out := make([]ZKBVar, c.Rq.N)
	coeffs := make([]*big.Int, c.Rq.N)
	c.Rq.PolyToBigint(x, coeffs)
	for i := uint64(0); i < c.Rq.N; i++ {
		out[i] = ZKBVar{coeffs[i], []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}, nil, nil, nil, nil}
	}
	return out
}

//RQVarFromZqArray transforms an array of ZKBVar with shares in Zq into a ZKBVar with shares in Rq
func (c *Circuit) RqVarFromZqArray(coeffs []ZKBVar) ZKBVar {
	out := ZKBVar{nil, nil, nil, nil, nil, make([]*lr.Poly, len(coeffs[0].shares))}
	for i := 0; i < len(out.rqShares); i++ {
		buf := make([]*big.Int, len(coeffs))
		for j, value := range coeffs {
			buf[j] = value.shares[i]
		}
		out.rqShares[i] = c.Rq.NewPoly()
		c.Rq.SetCoefficientsBigint(buf, out.rqShares[i])
	}
	return out
}

//Copy copies var v and returns it
func (c *Circuit) CopyVar(v ZKBVar) (z ZKBVar) {
	if v.Value != nil {
		z.Value = Copy(v.Value)
	}
	if v.Z2Value != nil {
		z.Z2Value = Copy(v.Z2Value)
	}
	if v.RqValue != nil {
		z.RqValue = c.Rq.NewPoly()
		c.Rq.Copy(v.RqValue, z.RqValue)
	}
	if v.shares != nil {
		z.shares = make([]*big.Int, len(v.shares))
		for i := range z.shares {
			z.shares[i] = Copy(v.shares[i])
		}
	}

	if v.z2Shares != nil {
		z.z2Shares = make([]*big.Int, len(v.z2Shares))
		for i := range z.z2Shares {
			z.z2Shares[i] = Copy(v.z2Shares[i])
		}
	}

	if v.rqShares != nil {
		z.rqShares = make([]*lr.Poly, len(v.rqShares))
		for i := range z.rqShares {
			z.rqShares[i] = c.Rq.NewPoly()
			c.Rq.Copy(v.rqShares[i], z.rqShares[i])
		}
	}
	return
}
