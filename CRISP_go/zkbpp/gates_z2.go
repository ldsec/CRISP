package zkbpp

import (
	"math/big"
)

type bitDecGate func([]*big.Int, *Circuit) []*big.Int
type z2gate func([]*big.Int, []*big.Int, *Circuit) []*big.Int
type z2gateInt func([]*big.Int, uint, *Circuit) []*big.Int
type z2gateFast func([]uint32, []uint32, *Circuit) []uint32

type z2gates struct {
	//bitdec
	bitDec bitDecGate
	//basic
	xor        z2gate
	or         z2gate
	not        z2gate
	and        z2gate
	rightShift z2gateInt
	add        z2gate
	addk       z2gate
	//SHA specific
	add32         z2gate
	addk32        z2gate
	rightRotate32 z2gateInt
	//SHA fast
	xorFast           z2gateFast
	orFast            z2gateFast
	andFast           z2gateFast
	rightShiftFast    z2gateFast
	rightRotate32Fast z2gateFast
	addFast           z2gateFast
	addkFast          z2gateFast
	e                 int
}

var z2evalGate = z2gates{
	//bitdec
	mpcBitDec,
	//basic
	mpcZ2Xor,
	mpcZ2Or,
	mpcZ2Not,
	mpcZ2And,
	mpcZ2RightShift,
	mpcZ2Add,
	mpcZ2AddK,
	//SHA specific
	mpcZ2Add32,
	mpcZ2AddK32,
	mpcZ2RightRotate32,
	//fast
	mpcZ2XorFast,
	mpcZ2OrFast,
	mpcZ2AndFast,
	mpcZ2RightShiftFast,
	mpcZ2RightRotate32Fast,
	mpcZ2AddFast,
	mpcZ2AddKFast,
	0,
}

var z2verifGate = z2gates{
	//bitdec
	mpcBitDecVerif,
	//basic
	mpcZ2XorVerif,
	mpcZ2OrVerif,
	mpcZ2NotVerif,
	mpcZ2AndVerif,
	mpcZ2RightShiftVerif,
	mpcZ2AddVerif,
	mpcZ2AddKVerif,
	//SHA specific
	mpcZ2Add32Verif,
	mpcZ2AddK32Verif,
	mpcZ2RightRotate32Verif,
	//fast
	mpcZ2XorFastVerif,
	mpcZ2OrFastVerif,
	mpcZ2AndFastVerif,
	mpcZ2RightShiftFastVerif,
	mpcZ2RightRotate32FastVerif,
	mpcZ2AddFastVerif,
	mpcZ2AddKFastVerif,
	0,
}

var z2preprocessGate = z2gates{
	//bitdec
	mpcZ2BitDecPreprocess,
	//basic
	mpcZ2NoOp,
	mpcZ2Preprocess,
	mpcZ2NoOp,
	mpcZ2Preprocess,
	mpcZ2NoOpInt,
	mpcZ2AddPreprocess,
	mpcZ2AddPreprocess,
	//SHA specific
	mpcZ2Add32Preprocess,
	mpcZ2Add32Preprocess,
	mpcZ2NoOpInt,
	//fast
	mpcZ2NoOpFast,
	mpcZ2PreprocessFast,
	mpcZ2PreprocessFast,
	mpcZ2NoOpFast,
	mpcZ2NoOpFast,
	mpcZ2AddPreprocessFast,
	mpcZ2AddPreprocessFast,
	0,
}

//The declaration for these functions are in separate files
