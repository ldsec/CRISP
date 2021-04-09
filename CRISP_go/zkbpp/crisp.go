package zkbpp

import (
	"github.com/ldsec/lattigo/ckks"
	lr "github.com/ldsec/lattigo/ring"
)

//DefaultParamsCRISP returns the default parameters of a CKKS scheme
func DefaultParamsCRISP() *ckks.Parameters {
	return ckks.DefaultParams[ckks.PN12QP109]
}

//MpcCRISP runs the CRISP circuit
func (c *Circuit) MpcCRISP(r0, e0, e1 ZKBVar, message, rc []ZKBVar, a1, a2 [][]*lr.Poly, pk [2]*lr.Poly) (ct0, ct1 ZKBVar, bdop1, bdop2 []ZKBVar, h []ZKBVar) {
	//commitmentBlock
	bdop1, bdop2 = c.MpcBdop(rc, r0, e0, e1, a1, a2)

	//encryption block
	pt := c.RqVarFromZqArray(message)
	ct0, ct1 = c.MpcCKKSEncrypt(pt, r0, e0, e1, pk)

	//conversion and hashblock
	//set the hash
	h = make([]ZKBVar, len(message))
	for i := 0; i < len(h); i++ {
		b := c.MpcBitDec(message[i])
		h[i] = c.MpcZ2ShaFast(b)
	}
	return
}

//MpcBdop computes the BDOP commitment for r0, e0, e1, given secret parameters rc and public matrices a1 and a2
//MpcBdop will panic if the dimension of a1,a2 and rc does not match
func (c *Circuit) MpcBdop(rc []ZKBVar, r0, e0, e1 ZKBVar, a1, a2 [][]*lr.Poly) (c1, c2 []ZKBVar) {

	k := len(rc)
	n := len(a1)

	//size check
	if len(a1[0]) != k-n || len(a2) != 3 || len(a2[0]) != k-n-3 {
		panic("incorrect size for matrices A in BDOP commitment")
	}

	//ouptut
	c1 = make([]ZKBVar, n)
	c2 = make([]ZKBVar, 3)

	// c1 = A1 * rc
	for i := 0; i < n; i++ {
		c1[i] = c.CopyVar(rc[i])
		for j := 0; j < k-n; j++ {
			c1[i] = c.MpcRqAdd(c1[i], c.MpcRqMultK(rc[n+j], a1[i][j]))
		}
	}

	//c2 = A2 * rc + (r0,e1,e0)
	for i := 0; i < 3; i++ {
		c2[i] = c.CopyVar(rc[n+i])
		for j := 0; j < k-n-3; j++ {
			c2[i] = c.MpcRqAdd(c2[i], c.MpcRqMultK(rc[n+3+j], a2[i][j]))
		}
	}
	c2[0] = c.MpcRqAdd(c2[0], r0)
	c2[1] = c.MpcRqAdd(c2[1], e0)
	c2[2] = c.MpcRqAdd(c2[2], e1)

	return
}

//MpcCKKSEncrypt encrypt pt with public key, using encryption noise r0,e0 and e1
//pt should be a ZKBVar with shares in Rq
//ct0 and ct1 are ZKBVar with shares in Rq
func (c *Circuit) MpcCKKSEncrypt(pt, r0, e0, e1 ZKBVar, pk [2]*lr.Poly) (ct0, ct1 ZKBVar) {

	//ct0 = r0 * pk[0] + pt + e0
	tmp := c.MpcRqMultK(r0, pk[0])
	tmp2 := c.MpcRqAdd(pt, e0)
	ct0 = c.MpcRqAdd(tmp, tmp2)

	//ct1 = r0 * pk[1] + e1
	tmp = c.MpcRqMultK(r0, pk[1])
	ct1 = c.MpcRqAdd(tmp, e1)

	return
}

//CKKSDecrypt decrypt ct0 and ct1 with secret key sk
func (c *Circuit) CKKSDecrypt(ct0, ct1 *lr.Poly, sk *lr.Poly) (pt *lr.Poly) {
	//pt = <ct,(1,sk)> = ct0 + ct1 * sk
	tmp1 := c.Rq.NewPoly()
	pt = c.Rq.NewPoly()
	c.Rq.MulCoeffs(ct1, sk, tmp1)
	c.Rq.Add(ct0, tmp1, pt)

	return
}
