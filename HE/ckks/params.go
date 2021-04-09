package ckks

import (
	"errors"
	"fmt"
	"github.com/ldsec/lattigo/utils"
	"math"
)

// Parameters is a struct storing the necessary parameters to instantiate a new ckkscontext.
//
// logN : the ring degree such that N = 2^logN
//
// modulichain : a list of moduli in bit size, such that prod(moduli) <= logQ, where logQ is the maximum bit size of the product of all the moduli
// for a given security parameter. This moduli chain allows to customize the value by which the ciphertexts will be rescaled allong the homomorphic computations,
// and can enhance performances for optimized applications.
//
// logScale : the default scale of the scheme such that scale = 2^logScale
//
// sigma : the variance used by the ckkscontext to sample gaussian polynomials.
type Parameters struct {
	LogN        uint8
	Modulichain []uint8
	P           []uint8
	Scale       float64
	Sigma       float64
}

// DefaultParams is a set of default CKKS parameters ensuring 128 bit security.
var DefaultParams = map[uint64]*Parameters{
	11: {11, []uint8{45}, []uint8{45}, 1 << 25, 3.2},
	12: {12, []uint8{31, 25}, []uint8{40}, 1 << 25, 3.2},
	122: {12, []uint8{28, 20, 20, 20}, []uint8{18}, 1 << 20, 3.2}, // - for SM2 with cumulative billing function       														                          //logQ = 107                                                                                                                                   //logQ = 109
	13: {13, []uint8{20, 20, 24, 24, 24, 24, 24, 24}, []uint8{24}, 1 << 24, 3.2}, //13: {13, []uint8{23, 23, 23, 23, 23, 23, 23, 23}, []uint8{33}, 1 << 23, 3.2},  working
	//13: {13, []uint8{22, 22, 22, 22, 22, 22, 22, 22}, []uint8{31}, 1 << 22, 3.2} simulation give 4percent error avg                                                                                 //logQ = 209
	14: {14, []uint8{45, 34, 34, 34, 34, 34, 34, 34, 34, 34}, []uint8{43, 43}, 1 << 34, 3.2},                                                                                                         //logQ = 415
	15: {15, []uint8{50, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40}, []uint8{50, 50, 50}, 1 << 40, 3.2},                                                                     //logQ = 831
}

// MaxN is the largest supported polynomial modulus degree
const MaxLogN = 16

// MaxModuliCount is the largest supported number of moduli in the RNS representation
const MaxModuliCount = 34

// Equals compares two sets of parameters for equality
func (p *Parameters) Equals(other *Parameters) bool {
	if p == other {
		return true
	}
	return p.LogN == other.LogN && utils.EqualSliceUint8(p.Modulichain, other.Modulichain) && p.Scale == other.Scale && p.Sigma == other.Sigma
}

// MarshalBinary returns a []byte representation of the parameter set
func (p *Parameters) MarshalBinary() ([]byte, error) {
	if p.LogN == 0 { // if N is 0, then p is the zero value
		return []byte{}, nil
	}
	b := utils.NewBuffer(make([]byte, 0, 7+((2+len(p.Modulichain))<<3)))
	b.WriteUint8(uint8(p.LogN))
	b.WriteUint8(uint8(len(p.Modulichain)))
	b.WriteUint8(uint8(len(p.P)))
	b.WriteUint64(uint64(p.Scale))
	b.WriteUint64(uint64(p.Sigma * (1 << 32)))
	b.WriteUint8Slice(p.Modulichain)
	b.WriteUint8Slice(p.P)
	return b.Bytes(), nil
}

// UnMarshalBinary decodes a []byte into a parameter set struct
func (p *Parameters) UnMarshalBinary(data []byte) error {
	if len(data) < 3 {
		return errors.New("invalid parameters encoding")
	}
	b := utils.NewBuffer(data)
	p.LogN = b.ReadUint8()
	if p.LogN > MaxLogN {
		return errors.New("polynomial degree is too large")
	}
	lenModulichain := uint64(b.ReadUint8())
	if lenModulichain > MaxModuliCount {
		return fmt.Errorf("len(Modulichain) is larger than %d", MaxModuliCount)
	}
	lenP := uint64(b.ReadUint8())
	if lenP > MaxModuliCount {
		return fmt.Errorf("len(P) is larger than %d", MaxModuliCount)
	}

	p.Scale = float64(b.ReadUint64())

	p.Sigma = math.Round((float64(b.ReadUint64())/float64(1<<32))*100) / 100
	p.Modulichain = make([]uint8, lenModulichain, lenModulichain)
	b.ReadUint8Slice(p.Modulichain)
	p.P = make([]uint8, lenP, lenP)
	b.ReadUint8Slice(p.P)
	return nil
}
