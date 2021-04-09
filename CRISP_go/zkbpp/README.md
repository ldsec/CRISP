# zkbpp

## Brief description
The package `zkbpp` offers an implementation of all the required building blocks to instantiate ZKCE circuits with preprocessing.

## Overview
- `circuit.go`: datatypes and util functions definition such as circuit creation, circuit mode selectors and random generators
- `circuit_gates.go`: gates that can be used to describe circuits, unless described in the function name such as Rq or Z2, those are assumed to work in the modular arithmetic ring
- `circuit_var.go`: datatype to describe a variable embedding its value and/or shares
- `crisp.go`: CRISP specific gates
- `gates_z2_[rq, z2, basic, bitdec, sha, shaFast, zq].go`: implementation of evaluation and verification of helper [rq, z2, basic, bitdec, sha, shaFast, zq] gates
- `proof.go`: proof generation and verification
- `sha.go`: sha implementations
- `z2Ring.go`: basic Z2 ring implementation
