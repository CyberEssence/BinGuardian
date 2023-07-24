# dll_injection_checker
This script on WinApi and Cpp checking exising of dll injection in Windows 10

# how to use this script?
Firstly, you can use the following commands on Ubuntu:

sudo apt update

sudo apt install mingw-w64

This commands needed to compile the script and create exe file to your Windows System.

Then, you can compile the script with following command and setuped MinGW:

x86_64-w64-mingw32-g++ -o dll_injection.exe dll_injection.cpp -lpsapi

Lastly, copy the exe file to the Windows system and run it, and before copying, disable the Windows Defender
WD would be delete this exe file, because WD recognize it for virus
In the future will be added the support of WD (hoping on this)
