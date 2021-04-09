This software and its source code are provided solely for the purpose of the peer-review process of Submission #71
to the 30th Usenix Security Symposium (2021). All other uses are forbidden.

This part was implemented in C building on an implementation of ZKBoo provided by https://github.com/Sobuno/ZKBoo

Run:  

~~~
gcc -c ZKBpp_bool.c -o boolcir; gcc -lcrypto -fopenmp boolcir -lm;gcc -lcrypto -fopenmp ZKBpp_bool_VERIFIER.c -o boolVerif
~~~

Running  

~~~
./a.out
~~~

will prompt a request for the integer to be converted.    
A circuit implementing the conversion block and SHA-256 is hard coded in ZKBpp_bool.c and shared.h.  

It will output out219.bin corresponding to the proof for 219 iterations of the ZKBpp protocol.  

Running  

~~~
./boolVerif
~~~

will verify the proof.  

All execution times are appended to the respective .csv files TimeProve.csv and TimeVer.csv.
