# ring

## Brief description
The package `ring` offers a basic implementation of modular arithmetic ring as well as a few operations on it.

## Overview
1. Create a new ring modulo 10 with `r = NewRing(big.NewInt(10))`
2. Add two aribraty-precision numbers in the ring `r` with `a = r.Add(big.NewInt(7), big.NewInt(8))` where `a` should be equal to 5

## Available operations
- Reduction
- Addition
- Subtraction
- Multiplication
- Negation
