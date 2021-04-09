//Package ring implement an integer ring with basic operations on big.Int in this ring
package ring

import (
	"math/big"
)

//Ring represents a ring of integers with modulo Q
type Ring struct {
	Q *big.Int
}

//NewRing returns a ring with given modulo Q
func NewRing(q *big.Int) *Ring {
	return &Ring{Q: q}
}

//Red reduces a big.Int a modulo r.Q
func (r *Ring) Red(a *big.Int) (c *big.Int) {
	c = big.NewInt(0)
	c.Mod(a, r.Q)
	return
}

//Add adds a and b in ring r
func (r *Ring) Add(a, b *big.Int) (c *big.Int) {
	c = big.NewInt(0)
	c.Add(a, b)
	c.Mod(c, r.Q)
	return
}

//Sub subs b to a in ring r
func (r *Ring) Sub(a, b *big.Int) (c *big.Int) {
	c = big.NewInt(0)

	c.Sub(a, b)
	if c.Cmp(big.NewInt(0)) == -1 {
		c.Add(c, r.Q)
	}
	c.Mod(c, r.Q)
	return
}

//Mult mulitplies a to b in ring r
func (r *Ring) Mult(a, b *big.Int) (c *big.Int) {
	c = big.NewInt(0)
	c.Mul(a, b)
	c.Mod(c, r.Q)
	return
}

//Neg returns -a in ring r
func (r *Ring) Neg(a *big.Int) (c *big.Int) {
	c = big.NewInt(0)
	c.Sub(r.Q, a)
	return
}
