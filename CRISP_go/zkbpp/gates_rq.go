package zkbpp

import (
	lr "github.com/ldsec/lattigo/ring"
)

type rqgate func([]*lr.Poly, []*lr.Poly, *Circuit) []*lr.Poly

type rqgates struct {
	add   rqgate
	addk  rqgate
	multk rqgate
	e     int
}

var rqEvalGate = rqgates{
	mpcRqAdd,
	mpcRqAddK,
	mpcRqMultK,
	0,
}

var rqVerifGate = rqgates{
	mpcRqAddVerif,
	mpcRqAddKVerif,
	mpcRqMultKVerif,
	0,
}

var rqpreprocessGate = rqgates{
	mpcRqNoop,
	mpcRqNoop,
	mpcRqNoop,
	0,
}

func mpcRqAdd(x []*lr.Poly, y []*lr.Poly, c *Circuit) (z []*lr.Poly) {

	z = []*lr.Poly{c.Rq.NewPoly(), c.Rq.NewPoly(), c.Rq.NewPoly()}

	c.Rq.Add(x[0], y[0], z[0])
	c.Rq.Add(x[1], y[1], z[1])
	c.Rq.Add(x[2], y[2], z[2])

	return
}

func mpcRqAddK(x []*lr.Poly, k []*lr.Poly, c *Circuit) (z []*lr.Poly) {

	z = []*lr.Poly{c.Rq.NewPoly(), c.Rq.NewPoly(), c.Rq.NewPoly()}

	c.Rq.Copy(x[0], z[0])
	c.Rq.Copy(x[1], z[1])
	c.Rq.Copy(x[2], z[2])

	c.Rq.Add(x[c.rqGates.e], k[0], z[c.rqGates.e])

	return
}

//Multiply x by a constant K. len(x) should be 3, len(k) should be 1
func mpcRqMultK(x []*lr.Poly, k []*lr.Poly, c *Circuit) (z []*lr.Poly) {

	z = []*lr.Poly{c.Rq.NewPoly(), c.Rq.NewPoly(), c.Rq.NewPoly()}
	c.Rq.MulCoeffs(x[0], k[0], z[0])
	c.Rq.MulCoeffs(x[1], k[0], z[1])
	c.Rq.MulCoeffs(x[2], k[0], z[2])

	return
}

func mpcRqAddVerif(x []*lr.Poly, y []*lr.Poly, c *Circuit) (z []*lr.Poly) {

	z = []*lr.Poly{c.Rq.NewPoly(), c.Rq.NewPoly()}

	c.Rq.Add(x[0], y[0], z[0])
	c.Rq.Add(x[1], y[1], z[1])

	return
}

func mpcRqAddKVerif(x []*lr.Poly, k []*lr.Poly, c *Circuit) (z []*lr.Poly) {

	z = []*lr.Poly{c.Rq.NewPoly(), c.Rq.NewPoly()}

	c.Rq.Copy(x[0], z[0])
	c.Rq.Copy(x[1], z[1])

	//need to compute if view0 is reconstructed
	if c.rqGates.e == 0 {
		c.Rq.Add(x[0], k[0], z[0])
	}

	//view0 has been sent, we need to add k to it
	if c.rqGates.e == 2 {
		c.Rq.Add(x[1], k[0], z[1])
	}

	return
}

func mpcRqMultKVerif(x []*lr.Poly, k []*lr.Poly, c *Circuit) (z []*lr.Poly) {

	z = []*lr.Poly{c.Rq.NewPoly(), c.Rq.NewPoly()}

	c.Rq.MulCoeffs(x[0], k[0], z[0])
	c.Rq.MulCoeffs(x[1], k[0], z[1])

	return
}

func mpcRqNoop(x []*lr.Poly, k []*lr.Poly, c *Circuit) (z []*lr.Poly) { return }
