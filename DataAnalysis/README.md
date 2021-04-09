This software and its source code are provided solely for the purpose of the peer-review process of Submission #71
to the 30th Usenix Security Symposium (2021). All other uses are forbidden.  

This folder contains the results of the different experiments:   

- Garmin/ for the location-based activity-tracking   
- Genomic/ for the genomic data  
- SmartMeters/ for the UKPN dataset  

In each of the .csv files, the following columns are considered:    
  - Name - file name  
  - logn - Degree of the polynomial ring  
  - logq - Modulus of the polynomial ring  
  - points - Number of datapoints in the file  
  - RealRes - Groundtruth  
  - result - Returned result  
  - error - Relative error   
  - tinit, tcsv, tenc, tdist, tdec - Times in ms to initialise the cipher, load the csv, encrypt, compute, and decrypt.   

The Garmin/ folder also contains the traces distribution: t represent the time between two samples, d the distance between two points, and V the instant speed.  

In order to access the analysis, open dataAnalysis.ipynb using jupyter lab or jupyter notebook.  

The ZKCEtimings/ folder contains the experiments for the ZKCE. Each file timingsXX.cdsv contains the result of the experiment for the ring with logq=XX.

Finally, the files boolCirTime128.csv and boolCirTimeVer128.csv correspond to the Boolean circuit experiment (Conversion and Hash blocks).
