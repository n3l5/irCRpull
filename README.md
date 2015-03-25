# irCRpull
irCRpull is a PowerShell script utilized to pull several system artifacts, utilizing the free tool CrowdResponse, from a live Win7+ system on your network.

Crowdstrike CrowdResponse - http://www.crowdstrike.com/community-tools/index.html

[Important]
The CrowdResponse download includes a default/sample config.txt

This script specifies the CrowdResponse.exe options via "-i config.txt". Alternatively, you can edit the script to manually specify the commands run time instructions. 
The config.txt is important for getting the results you want from the system; look at it, tweak it, test it... (it is up to you)

It will dump the data into .xml files/reports in the $dumpdir you specify (later packed and pulled).
	
When done collecting the artifacts, it will 7zip the data and pull the info off the box for offline analysis.

See the script for more info.
