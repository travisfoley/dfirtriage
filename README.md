# **dfirtriage**
Digital forensic acquisition tool for Windows based incident response.

How to Use
=
To run, drop dfirtriage.exe on the target and execute with admin rights. 

***************************************************************************************

**DFIRTriage v3.0.0 User's Manual**
=

Description
-----------

This document outlines the functionality and proper use of the DFIRTriage tool. Also included is detailed information to help with analysis of the output.  

About
-----

DFIRTriage is a tool intended to provide Incident Responders with rapid host data. Written in Python, the code has been compiled to eliminate the dependency of python on the target host. The tool will run a variety of commands automatically upon execution. The acquired data will reside in the root of the execution directory. DFIRTriage may be ran from a USB drive or executed in remote shell on the target. Windows-only support. 

What’s New?
-----------

 * No dependencies. DFIRTriage 3.0 is now a self-contained executable. All dependencies required with previous versions have been eliminated.
 
 * Prompt removed, new command line options available.
     The following options are available when runnning from the commandline:  

        (-m) Executes all options and acquires memory

        (-ho) Only hashes files on the target, no other operations are performed

        (-bo) Only collects browser history information, no other operations are performed

        (-h) Shows help message

        (none) Running with no option (e.g. double-click) will execute all options except for memory acquisition

Dependencies
-
The tool repository contains the full toolset required for proper execution and is packed into a single a single file named “core.ir”. This “.ir” file is the only required dependency of DFIRTriage when running in Python and should reside in a directory named data, (ie. "./data/core.ir").  The compiled version of DFIRTriage now has the tools file embedded and does not require the addition of the "./data/core.ir" file.  Please note that the demo version of select TZWorks tools are used in the public release of DFIRTriage. Licensed copies may be purchased at www.tzworks.com. 

Contents
-
 * DFIRTriage.exe 
   - compiled executable
 * .\data\core.ir
   - tool set repository (required for Python version only)
 * manifest.txt
   - hash list for core components
 * unlicense.txt
   - copy of license agreement
 * source directory
   - DFIRTriage3.0.0_PUB.py

Operation
-
DFIRTriage acquires data from the host on which it is executed. For acquisitions of remote hosts, the DFIRTriage files will need to be copied to the target, then executed via remote shell. (ie. SSH or PSEXEC)  

PSEXEC Usage
-
*WARNING: Do not use PSEXEC arguments to pass credentials to a remote system for authentication. Doing so will send your username and password across the network in the clear.*  

**The following steps should be taken for proper usage of PSEXEC** 

 1. Map a network drive and authenticate with an account that has local administrative privileges on the target host.
> You can used this mapped connection to copy the DFIRTriage zip file
> over to the target host and extract the files to a temp directory.

 2. We can now shovel a remote shell to the target host using PSEXEC.

    psexec \\\\target_host cmd

 3. You now have a remote shell on the target. All commands executed at this point are done so on the target host. 


Usage

1. Once the remote shell has been established on the target you can change directory to the location of the extracted DFIRTriage.exe file and execute. 

2. Memory acquisition is controlled by command line arguments. To acquire memory, the "-m" commandline argument should be used. Memory acquisition is bypassed by default. 

3. DFIRTriage must be executed with Administrative privileges.


Output Analysis
-
Once the script has completed, the final action is to clean up the output directory. If running the compiled executable, the only data remaining with be a zipped archive of the output as well as DFIRTriage.exe. If running the Python code directly the "./data/core.ir", DFIRTriage3_PUB.py, and a zipped archive of the output are left.   

Output Folder
-
The output folder name includes the target hostname and a date/time code indicating when DFIRTriage was executed.  The date/time code format is YYYYMMDDHHMMSS.    

Artifacts List
=
The following is a general listing of the information and artifacts gathered.  

* **Browser History** --> browser history collection from multiple browsers

* **Memory Raw** --> image acquisition (optional) 

* **Prefetch** --> Collects all prefetch files an parses into a report 

* **User activity** --> HTML report of recent user activity 

* **System32 file hash** --> MD5 hash of all files in root of System32 

* **Network information** --> Network configuration, routing tables, etc 

* **Extended process lis**t --> Processes, PID, and image path 

* **Windows character code page information** --> Character set that Windows is using 

* **Complete file listing** --> Full list of all files on the system partition 

* **List of hidden directories** --> List of all hidden directories on the system partition 

* **Current user information** --> User running DFIRTriage script 

* **System information** --> Build, service pack level, installed patches, etc 

* **Windows version** --> Logs the version number of the target OS 

* **Current date and time** --> Current system date and time 

* **List of scheduled tasks** --> List of all configured scheduled tasks 

* **Loaded processes and dlls** --> List of all running processes and loaded dlls 

* **Running processes** --> Additional information on running processes 

* **Network configuration** --> Network adaptor configuration 

* **Network connections** --> Established network connections 

* **Open TCP/UDP ports** --> Active open TCP or UDP ports 

* **DNS cache entries** --> List of complete DNS cache contents 

* **ARP table information** --> List of complete ARP cache contents 

* **Local user account names** --> List of local user accounts 

* **NetBIOS information** --> Active NetBIOS sessions, transferred files, etc 

* **Installed software** --> List of all installed software through WMI 

* **Autorun information** --> All autorun locations and content 

* **List of remotely opened files** --> Files on target system opened by remote hosts 

* **Logged on users** --> All users currently logged on to target system 

* **Alternate Data Streams** --> List of files containing alternate data streams 

* **Registry hives** --> Copy of all registry hives 

* **USB artifacts** --> Collects data needed to parse USB usage info 

* **Hash of all collected triage data** --> MD5 hash of all data collected by DFIRTriage 

