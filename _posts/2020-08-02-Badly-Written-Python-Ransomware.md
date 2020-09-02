---
title:  "Cyrat: A badly written Ransomware"
layout: post
---

![Ransomware encrypt func](/assets/images/Blog-0/banner.PNG)  

Today I came across the simplest ransomware that I've ever seen, and it'ss badly written too... So why not make it the subject of the 1st blog? :)  

## Initial Analysis  
The binary's size is 12 MB... kinda hard to distribute :)  

Running [FLOSS](https://github.com/fireeye/flare-floss) (Strings) reveales why the binary is 12 MB  
  
![FLOSS output](/assets/images/Blog-0/img0.PNG)  

The binary is written in Python, then the .pyc and library files are bundled into a stand-alone executable using py2exe or pyinstaller (too lazy for C++ huh?)  

Time to extract and "uncompyle" the binary back to the original .py files. This requires [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor),
python 3.7, and [uncompyle6](https://pypi.org/project/uncompyle6/). The code reside in the file called "Microsoft_dll_fix.py".  

## Behavior
![welcome_screen func](/assets/images/Blog-0/img3.PNG)  
  
Looking at the Welcome_screen function, the ransomware disguises as a "DLL fixer" tool.  
It targets files with these extensions:  
![extensions](/assets/images/Blog-0/img2.PNG)  
