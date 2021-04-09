This software and its source code are provided solely for the purpose of the peer-review process of Submission #71
to the 30th Usenix Security Symposium (2021). All other uses are forbidden.

This part of is implemented in C++ on a SNUCrypto library tailored for lattices operations over polynomial rings.  
In order to run the arithmetic part of the ZKCE, one should first build HEAAN. Please adapt the parameter in run/runMPCmult.cpp but also in the src/params.h to the use case considered. By deafult, it is set for smart metering.  

~~~
cd ZKCE_arith/lib
make all
~~~

Then from the /run directory, select in the makefile which script to build and run:  

~~~
make
~~~

This creates an executable that can be run launching:  

~~~
./MPCmult
~~~

This creates a dummy vector, encrypts it, and commits to the encryption noises. 
The encryption parameters can be configured in /src/params.h.  

Running ./MPCmult triggers one iteration of the protocol. By running automaton.sh one can evaluate the timings for 219 iterations of the protocol.
