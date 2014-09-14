# PseudoWall

A script to emulate the CryptoWall C2 server, nothing more, nothing less. To be used as an aid in studying the malware's behaviour in a lab environment. If you're looking for a example of awesome Python, keep moving.. 

## Getting Started

You'll need a standlone network for malware analysis; plenty of resources on the 'net on how to set one up. Suffice it to say, make sure this is plenty separate from your real machines, unless you want practice at reinstalling Windows/Linux! ;-)

My setup for this exercise were two VMs, one malware fodder (Windows) and one Linux machine. The Linux machine runs a wildcard DNS responder (fakedns.py), which answers any DNS query with it's own IP. You can use something like ApateDNS if this machine needs to be Windows. PseudoWall is then updated with the IP of the fake C2 server, and run.

Once you've got this setup, and again checked the environment is isolated, check to make sure your environment is isolated! Then execute CryptoWall on the pawn machine. You can then observe the malware contacting the C2 (this script), downloading the key, and crypt'ing the files. You should see the ransom note assuming all this went well. 

The script is commented, so should be self explanatory and help with understanding the command structure CryptoWall uses. 

# Disclaimer 

Malware obviously changes frequently, this may not work for samples much more recent than September 2014. This C2 format seems to have been in use for at least 6 months, so it's anyones guess how much longer it will be used.
