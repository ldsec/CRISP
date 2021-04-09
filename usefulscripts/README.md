This software and its source code are provided solely for the purpose of the peer-review process of Submission #71
to the 30th Usenix Security Symposium (2021). All other uses are forbidden.

This readme epxlains how to pre-process the GPS location traces collected from Garmin connect.


# Preprocessing of location data 
Requires gpsbabel and the utm python library and Python3. They can be installed using pip:  

```
pip install gpsbabel
pip install utm
```

Scripts used for pre-processing the Garmin GPS location trace dataset can be found in the usefulscripts/ directory.
Fill the datatest/ directory with the .txt traces you want to process. They should be in a csv format:

```
No,Latitude,Longitude,Speed,Date(YYYY/MM/DD),Time(HH:MM:SS)
```
Then simply run ./auto.sh. 
