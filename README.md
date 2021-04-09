# CRISP

This repository comprises an implementation of CRISP [1]: a novel solution that achieves utility, privacy, and integrity in the three-party model comprising a data source, a user, and a service provider.

In a nutshell, CRISP relies on quantum-resistant lattice-based approximate homomorphic encryption (HE) primitives [2] that support flexible polynomial computations on encrypted data without degrading utility. To ensure data integrity, we employ lattice-based commitments [3] and zero-knowledge proofs based on the multi-party-computation-in-the-head (or MPC-in-the-head) paradigm [4], which enable users to simultaneously convince service providers about the correctness of the encrypted data, as well as the authenticity of the underlying plaintext data, using the deployed certification mechanism.

A complete unified implementation of CRISP is implemented in Golang and available in the CRISP_go directory.

References:

[[1](https://www.usenix.org/conference/usenixsecurity21/presentation/chatel)] Chatel et al., "Privacy and Integrity Preserving Computations with CRISP", USENIX Security, 2021. 

[[2](https://eprint.iacr.org/2016/421.pdf)] Cheon et al., "Homomorphic encryption for arithmetic of approximate numbers", ASIACRYPT, 2017.

[[3](https://eprint.iacr.org/2016/997)] Baum et al., "More Efficient Commitments from Structured Lattice Assumptions", SCN, 2018. 

[[4](https://eprint.iacr.org/2017/279.pdf)] Chase et al., "Post-Quantum Zero-Knowledge and Signatures from Symmetric-Key Primitives", CCS, 2017. 

# CRISP_go
Unified implementation of CRISP in Golang.  


# ZKCE 
CRISP's cicuit evaluated in the paper is implemented in two parts: ZKCE_bin and ZKCE_arith.  

## ZCKE_bin
This directory contains the implementation of the conversion block and hash block of our soluton and evaluated in the paper. This part was implemented in C building on an implementation of ZKBoo provided by https://github.com/Sobuno/ZKBoo. Please look at the readme in the corresponding directory for further details. 

## ZKCE_arith 
This directory contains the implementation of the arithmetic part of the ZKCE evaluated in the paper: the encryption and commitment blocks. This part is implemented in C++ on top of a SNUCrypto library tailored for lattices operations over polynomial rings. Please look at the readme in the corresponding directory for further details. 

# Homomorphic Encryption 
This directory contains the code to evaluate the computations required for the three use-cases presented in the paper. It uses a standalone version of the Lattigo library. Please look at the readme in the corresponding directory for further details.

# Datasets
For our experiments we used the following datasets:

- Smart metering: UKPN dataset https://data.london.gov.uk/dataset/smartmeter-energy-use-data-in-london-households
- Disease Susceptibility: 1000 Genomes https://www.internationalgenome.org/data
- Location Based Activity Tracking: Garmin Connect https://connect.garmin.com/  

The pre-processing steps of the Garmin connect dataset is presented in the usefulscripts/ directory. Please look at the readme in the corresponding directory for further details.

# Data Analysis 
In this directory we provide the results of our experiments on the different datasets. The .csv files are imported to the notebook dataAnalysis.ipnb for convenience.

