# CRISP-Go
This Repository comprises the implementation of ZKCE with preprocessing in Go using ZKB++<sup>[1](#myfootnote1)</sup> and KKW<sup>[2](#myfootnote2)</sup> with an application to CRISP<sup>[3](#myfootnote3)</sup>. This has been realized by Simon Wicky and Daniel Filipe Nunes Silva under the supervision of Sylvain Chatel at EPFL LDSEC lab.

## Run
1. Compile with `go build -o zkce`.
2. Run with `./zkce`.
3. You can now choose between running the CRISP<sup>[3](#myfootnote3)</sup> circuit by pressing 1 or a dummy alternative computing a law of cosines inspired function by pressing 2.
4. Finally the whole programm will execute for multiple iterations. You can observe the results from the preprocessing, proof generation and verification as well as a few sanity checks, i.e. decryptions, integrity and comittments.

## Overview
- `main.go`: basic code to run any of the two provided circuits
- `main_test.go`: a few basic tests and benchmarks
- `circuit_crisp.go`: description of the CRISP<sup>[3](#myfootnote3)</sup> circuit
- `circuit_dummy.go`: description of the dummy circuit computing a law of cosines inspired function
- `CRISP-private/ring`: basic modular ring implementation with addition, substraction, multiplication and negation operations
- `CRISP-private/zkbpp`: implementation of the whole ZKCE machinery, i.e. preprocessing, proofs generation and verification as well as all the available gates, CRISP<sup>[3](#myfootnote3)</sup> specific material and a MPC SHA-256 to describe further arithmetic or binary circuits.

## Documentation
1. Generate documentation local server wiht `godoc -http=localhost:6060`.
2. Visit http://localhost:6060/pkg/github.com/ldsec/CRISP-private/ for the full documentation.

## Dependencies
- The Go programming language from https://golang.org/
- The `lattigo/ring package` from https://github.com/ldsec/lattigo/ to use ring parameters and polynomials
- The `lattigo/utils` package from https://github.com/ldsec/lattigo/ to use pseudorandom number generators

## Disclaimer
This implementation is for research purposes only.

## Miscellaneous
The branch NoPreprocessing contains a ZKCE without preprocessing, along with benchmarks. The code is the result of an intermediate work and might not be cleaned and well documented.

## References
1. <a name="myfootnote1"></a> M. Chase, D. Derler, S. Goldfeder, C. Orlandi, S. Ramacher,
C. Rechberger, D. Slamanig, and G. Zaverucha, “Post-Quantum Zero- Knowledge and Signatures from Symmetric-Key Primitives,” CCS ’17.
2. <a name="myfootnote2"></a> Jonathan Katz, Vladimir Kolesnikov, and Xiao Wang. 2018. “Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures”, CCS '18.
3. <a name="myfootnote3"></a> S. Chatel, A. Pyrgelis, J.R. Troncoso-Pastoriza, and J.-P. Hubaux. “Privacy and Integrity Preserving Computations with CRISP”. arXiv preprint arXiv:2007.04025, 2020.
