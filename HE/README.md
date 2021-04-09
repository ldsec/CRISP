This software and its source code are provided solely for the purpose of the peer-review process of Submission #71
to the 30th Usenix Security Symposium (2021). All other uses are forbidden.

This part is implemented on the Lattigo Library v1.3.0 commit 119b84e80fa4e8f374b6b3d79c21ea318e1f24eb under Apache Lincence. It is provided as a standlone library within this repository for convenience. 

Our contribution can be found in the CRISP_HE/ directory. For convenience we also provide test data in the CRISP_HE/datatest/ directory.  

The different scripts are available depending on the use case (smart metering - SM, disease susceptibility - DS, and distance computation - Dist). We list them below: 

For XX in {SM, DS, Dist}:  

~~~
go build example_XX.go
~~~

Return a XX executable that can be ran with:  

~~~
./XX $i
~~~

with $i being the input file of the experiment.  

Launching one of the bash files autoXX.sh will run the experiment for all elements in the XX database.  

Each run of the executable will append results to the appropriate csv file.  

We note that our modification of the library resides in the ckks/params.go file to accommodate our specific moduli decompositions. 
