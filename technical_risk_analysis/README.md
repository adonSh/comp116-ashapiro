COMP116 Lab 9 -- Technical Risk Analysis
========================================
The Veracode scan and my results are not too dissimilar. I missed the
hard-coded passwords that Veracode identified in many of the php files, as well
as numerous cross-site scripting vulnerabilities that were not relevant to
finding keys in the game. The Veracode scan did not catch all the
vulnerabilities related to the keys being stored in plaintext or base64, but I
suppose there was no way for it to know that the keys were "sensitive
information." I wish the scan provided

	--Adon Shapiro
