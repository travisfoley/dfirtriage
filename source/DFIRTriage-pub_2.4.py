#!/usr/bin/env python

#############################################################################
##                                                                         ##
## Description: Forensic acquisition of volatile data and system           ##
## information for use with initial Incident Response.                     ##
##                                                                         ##
## License: Unlicense (http://unlicense.org)                               ##
##                                                                         ##
## Version: 2.4                                                            ##
## Filename: DFIRTriage.py                                                 ##
## Author: Travis Foley, travis.foley@gmail.com                            ##
## Last modified: : 4-20-16                                                ##
##                                                                         ##
#############################################################################

import os
import time
import socket
import sys
import ctypes
import subprocess
import shutil
import zipfile
import hashlib
import argparse

parser = argparse.ArgumentParser(description='First Responder acquisition of Windows system & user artifacts for IR.')
args = parser.parse_args()

debugMode = "off"

# Forcing stdout to flush so all print() and stdout.write() functions will display in the console when executing over a remote shell with ssh or psexec
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

os.system('color 0A')
print
print

print "#######################################################"
print "#                                                     #"
print "#  (     (    (   (                                   #"
print "#  )\ )  )\ ) )\ ))\ )    *   )                       #"
print "# (()/( (()/((()/(()/(  ` )  /((  (     ) (  (    (   #"
print "#  /(_)) /(_))/(_))(_))  ( )(_))( )\ ( /( )\))(  ))\  #"
print "# (_))_ (_))_(_))(_))   (_(_()|()((_))(_)|(_))\ /((_) #"
print "#  |   \| |_ |_ _| _ \  |_   _|((_|_|(_)_ (()(_|_))   #"
print "#  | |) | __| | ||   /    | | | '_| / _` / _` |/ -_)  #"
print "#  |___/|_|  |___|_|_\    |_| |_| |_\__,_\__, |\___|  #"
print "#                                        |___/        #"
print "#                  Version 2.4.1                      #"
print "#                                                     #"
print "#######################################################"

# [BEGIN] OS and Arch Detection
print
OSArch = 0
x64sys = "c:\Program Files (x86)"
# Check OS Type
if os.path.exists(x64sys):
    print "[+] Detecting OS and System Architecture... [64bit system, forcing 32bit]"
    OSArch = 32
# OSArch in the above line is forcing 32-bit detection

else:
	print "[+] Detecting OS and System Architecture... [32bit system]"
	OSArch = 32

	
# Integrity check

if os.path.isfile("core.ir"):
    print
    print "[+] Verifying core integrity..."
   
else:
    os.system('color 4F')
    print
    print "[!] The DFIRTriage package is incomplete. Please download a new copy."
   
    sys.exit()

hasher = hashlib.md5()
coreVal = "9850d56624900b2cf774f2f17887ba14"
with open('core.ir', 'rb') as corefile:
    buf = corefile.read()
    hasher.update(buf)
coreCheck = hasher.hexdigest()

if (coreVal == coreCheck):
    print
    print "[+] Core integrity... [OK]"
   
else:
    os.system('color 4F')
   
    print
    print "[!] Hash values do not match. Integrity check failed. Please download a new copy."
   
    sys.exit()

# Admin rights check
try:
 is_admin = os.getuid() == 0
except AttributeError:
 is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

if is_admin == False:
    print
    print "[+] Has Local Admin rights... [NO]"
    print
    open("DFIRTriage must be ran as Local ADMIN.txt", 'w')
    quit()    
else:
		print
		print "[+] Has Local Admin rights... [Yes]"
		print
		print "[+] Done."

# Prompt for memory acquisition

print
print "Do you want to acquire memory? (y | n)"
memCollection = raw_input()
print

# [END] OS and Arch Detection


# [BEGIN] Environment Setup

print
print "[+] Setting up environment..."
print

# Exporting tools
zip = zipfile.ZipFile(r'core.ir')
zip.extractall(r'.')  

# Case Folder
TargetName = socket.gethostname()
DateAndTime = time.strftime("%Y%m%d%H%M%S")
CaseFolder = TargetName+"."+DateAndTime

print
print "[+] Building acquisition directory structure..."

if not os.path.exists(CaseFolder):
    os.makedirs(CaseFolder)

os.makedirs(CaseFolder+'/ForensicImages')
os.makedirs(CaseFolder+'/ForensicImages/Memory')
os.makedirs(CaseFolder+'/ForensicImages/HDD')
os.makedirs(CaseFolder+'/LiveResponseData/BasicInfo')
os.makedirs(CaseFolder+'/LiveResponseData/UserInfo')
os.makedirs(CaseFolder+'/LiveResponseData/NetworkInfo')
os.makedirs(CaseFolder+'/LiveResponseData/PersistenceMechanisms')
os.makedirs(CaseFolder+'/LiveResponseData/Registry')
os.makedirs(CaseFolder+'/LiveResponseData/Registry/regripped-out')
os.makedirs(CaseFolder+'/LiveResponseData/Registry/usb-install-log')
os.makedirs(CaseFolder+'/LiveResponseData/Prefetch')
os.makedirs(CaseFolder+'/LiveResponseData/FileSystem')

# [END] Environment Setup


# [BEGIN] Memory acquisition
if memCollection == "y":
    print "[+] Memory acquisition..."
    print
    # variable to point to the "memory" subdir of current directory
    MemDir = os.path.realpath('.') + "/memory/"

    # setting up variables to run winpemem with different parameters
    MemAcqLoad = MemDir + "winpmem_1.6.2.exe -l"
    MemAcqGet = MemDir + "winpmem_1.6.2.exe memdump.raw"
    # MemAcqUnload = MemDir + "winpmem_1.6.2.exe -u" # Did not need to unload, this is done automatically when winpemem exits

    # executing winpmem
    subprocess.call(MemAcqLoad)
    subprocess.call(MemAcqGet)
    #subprocess.call(MemAcqUnload) # Did not need to unload, this is done automatically when winpemem exits

    # moving acquired memory image to case folder
    os.rename(os.path.realpath('.') + "/" + "memdump.raw", CaseFolder + "/ForensicImages/Memory" + "/" + "memdump.raw")

else:
    print
    print "[+] Skipping memory acquisition..."
    print

# [END] Memory acquisition

# [BEGIN] Prefetch Collection
print
print "[+] Prefetch collection..."
print

# Detecting system architecture
if os.path.exists("c:\windows\system32\\"):
	# variable to point to the location of "xcopy" on the remote system
	XcopyDir = "c:\windows\system32\\"
	# setting up variables to run xcopy with appropriate parameters
	XcopyParam = XcopyDir + "xcopy.exe /s/e/h/i/k C:\Windows\Prefetch\*.pf "
	XcopyOut = CaseFolder + "\LiveResponseData\Prefetch"
	XcopyPF = XcopyParam + XcopyOut

	# copying prefetch files from target
	subprocess.call(XcopyPF)

else:
	print
	print "Xcopy missing from target"


print

# [END] Prefetch Collection

# [BEGIN] Begin LastUser Activity Data Collection
print "[+] Last User Activity collection..."
print

# variable to point to the "lastactivityview" subdir of current directory
LAVDir = os.path.realpath('.') + "/lastactivityview/"


# setting up variables to run LastActivityView with output parameters
LAVRun = LAVDir + "LastActivityView.exe /shtml "
LAVParam = CaseFolder + "/LiveResponseData/BasicInfo" + "/LastActivityView.html"
LAVExe = LAVRun + LAVParam

# executing lastactivityview
subprocess.call(LAVExe)

print

# [END] Begin LastUser Activity Data Collection

# [BEGIN] Hashing System Data
print "[+] Hash system data..."
print

if debugMode == "off":
    if OSArch == 64:
        # variable to point to the "md5deep-4.4" subdir of current directory
        MD564Path = "%s\md5deep-4.4\md5deep64.exe" % (os.path.realpath('.'))
        # setting up system32 MD5 hashing parameters
        MD564Param1 = " -oe -u -t C:\Windows\System32\* "
        MD564Run1 = MD564Path + MD564Param1
        # hashing system32
        with open('Hashes_md5_System32_WindowsPE_and_Dates.txt', 'w') as fout:
            subprocess.call(MD564Run1, stdout=fout)
        # moving hash data to case folder
        os.rename(os.path.realpath('.') + "/" + "Hashes_md5_System32_WindowsPE_and_Dates.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Hashes_md5_System32_WindowsPE_and_Dates.txt")
        # setting up c:\temp MD5 hashing parameters
        MD564Param2 = " -oe -u -t -r C:\Temp\* "
        MD564Run2 = MD564Path + MD564Param2
        # hashing c:\temp
        with open('Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt', 'w') as fout:
            subprocess.call(MD564Run2, stdout=fout)
        # moving hash data to case folder
        os.rename(os.path.realpath('.') + "/" + "Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt")
        # setting up user temp MD5 hashing parameters
        UserTempDir = os.getenv('TEMP')
        MD564Param3 = " -oe -u -t -r %s\* " % (UserTempDir)
        MD564Run3 = MD564Path + MD564Param3
        # hashing user temp
        with open('Hashes_md5_User_TEMP_WindowsPE_and_Dates.txt', 'w') as fout:
            subprocess.call(MD564Run3, stdout=fout)
        # moving hash data to case folder
        os.rename(os.path.realpath('.') + "/" + "Hashes_md5_User_TEMP_WindowsPE_and_Dates.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Hashes_md5_User_TEMP_WindowsPE_and_Dates.txt")

    else:
        MD5Path = "%s\md5deep-4.4\md5deep.exe" % (os.path.realpath('.'))
        # setting up system32 MD5 hashing parameters
        MD5Param1 = " -oe -u -t C:\Windows\System32\* "
        MD5Run1 = MD5Path + MD5Param1
        # hashing system32
        with open('Hashes_md5_System32_WindowsPE_and_Dates.txt', 'w') as fout:
            subprocess.call(MD5Run1, stdout=fout)
        # moving hash data to case folder
        os.rename(os.path.realpath('.') + "/" + "Hashes_md5_System32_WindowsPE_and_Dates.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Hashes_md5_System32_WindowsPE_and_Dates.txt")
        # setting up c:\temp MD5 hashing parameters
        MD5Param2 = " -oe -u -t -r C:\Temp\* "
        MD5Run2 = MD5Path + MD5Param2
        # hashing c:\temp
        with open('Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt', 'w') as fout:
            subprocess.call(MD5Run2, stdout=fout)
        # moving hash data to case folder
        os.rename(os.path.realpath('.') + "/" + "Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt")
        # setting up user temp MD5 hashing parameters
        UserTempDir = os.getenv('TEMP')
        MD5Param3 = " -oe -u -t -r %s\* " % (UserTempDir)
        MD5Run3 = MD5Path + MD5Param3
        # hashing user temp
        with open('Hashes_md5_User_TEMP_WindowsPE_and_Dates.txt', 'w') as fout:
            subprocess.call(MD5Run3, stdout=fout)
        # moving hash data to case folder
        os.rename(os.path.realpath('.') + "/" + "Hashes_md5_User_TEMP_WindowsPE_and_Dates.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Hashes_md5_User_TEMP_WindowsPE_and_Dates.txt")
else:
    print "(i) DEBUG MODE: Skipping hash operation..."
# [END] Hashing System Data

# [BEGIN] Network Info Gathering
print
print "[+] Network information gathering..."

# setting up netstat and parameters
NetStatEXE = "C:\Windows\System32\NETSTAT.EXE"
NetStatEXEParams = " -anb"
NetStatRun = NetStatEXE + NetStatEXEParams

# running netstat
with open('netstat_anb_results.txt', 'w') as fout:
    subprocess.call(NetStatRun, stdout=fout)

# moving netstat info to case folder
os.rename(os.path.realpath('.') + "/" + "netstat_anb_results.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "netstat_anb_results.txt")

# [END] Network Info Gathering

# [BEGIN] Additional Volatile Data Gathering
print
print "[+] Gather additional volatile data..."
print
print "\t" + "[-] Collecting extended process list..."
print

# variable to point to the "pv.exe" subdir of current directory
PrcViewPath = "%s\PrcView\pv.exe" % (os.path.realpath('.'))

# setting up processview parameters
PrcViewParam1 = " -el "
PrcViewParam2 = " -e "
PrcViewRun1 = PrcViewPath + PrcViewParam1
PrcViewRun2 = PrcViewPath + PrcViewParam2

# running processview "extended long"
with open('PrcView_extended_long.txt', 'w') as fout:
    subprocess.call(PrcViewRun1, stdout=fout)

# running processview "extended"
with open('PrcView_extended.txt', 'w') as fout:
    subprocess.call(PrcViewRun2, stdout=fout)

# moving processview data to case folder
os.rename(os.path.realpath('.') + "/" + "PrcView_extended_long.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "PrcView_extended_long.txt")
os.rename(os.path.realpath('.') + "/" + "PrcView_extended.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "PrcView_extended.txt")

print "\t" + "[-] Collecting Windows character code page info..."
print

# variable to point to the Windows Code Page program under system32
CHCPcom = "%s\system32\chcp.com" % (os.getenv('WINDIR'))

# grabbing character code page info
with open('Windows_codepage.txt', 'w') as fout:
    subprocess.call(CHCPcom, stdout=fout)

# moving code page info to case folder
os.rename(os.path.realpath('.') + "/" + "Windows_codepage.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Windows_codepage.txt")

if debugMode == "off":
	print "\t" + "[-] Creating complete file listing..."
	print

	# setting up directory list command
	DirFileList = "cmd.exe /C dir C:\* /s/o-d"

	# running directory list
	with open('Full_file_listing.txt', 'w') as fout:
		subprocess.call(DirFileList, stdout=fout)

	# moving directory list to case folder
	os.rename(os.path.realpath('.') + "/" + "Full_file_listing.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Full_file_listing.txt")
else:
    print "(i) DEBUG MODE: Skipping file listing..."
    print
	
print "\t" + "[-] Creating list of hidden directories..."
print

# setting up netstat and parameters
HiddenDirList = "cmd.exe /C dir /S /B /AHD C:\Windows\*"

# running netstat
with open('List_hidden_directories.txt', 'w') as fout:
    subprocess.call(HiddenDirList, stdout=fout)

# moving code page info to case folder
os.rename(os.path.realpath('.') + "/" + "List_hidden_directories.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "List_hidden_directories.txt")

print "\t" + "[-] Logging user information..."
print
# setting up whoami command
UserInfo = "%s/whoami.exe" % (os.path.realpath('./winutils'))

# running whoami
with open('whoami.txt', 'w') as fout:
    subprocess.call(UserInfo, stdout=fout)

# moving code page info to case folder
os.rename(os.path.realpath('.') + "/" + "whoami.txt", CaseFolder + "/LiveResponseData/UserInfo" + "/" + "whoami.txt")

print "\t" + "[-] Logging system info..."
print
# setting up Windows version command
WinVer = "cmd.exe /C ver"

# running ver
with open('Windows_Version.txt', 'w') as fout:
	subprocess.call(WinVer, stdout=fout)

# moving version info to case folder
os.rename(os.path.realpath('.') + "/" + "Windows_Version.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Windows_Version.txt")

# setting up systeminfo command
SysInfo = "cmd.exe /C systeminfo"

# running systeminfo
with open('system_info.txt', 'w') as fout:
	subprocess.call(SysInfo, stdout=fout)

# moving systeminfo output to case folder
os.rename(os.path.realpath('.') + "/" + "system_info.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "system_info.txt")

print "\t" + "[-] Recording current date and time..."
print
# setting up date command
WinDate = "cmd.exe /C date /T"

# setting up time command
WinTime = "cmd.exe /C time /T"

# logging current date and time
with open('current_date_time.txt', 'w') as fout:
	subprocess.call(WinDate, stdout=fout)
	subprocess.call(WinTime, stdout=fout)

# moving date/time information to case folder
os.rename(os.path.realpath('.') + "/" + "current_date_time.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "current_date_time.txt")

print "\t" + "[-] Logging scheduled tasks..."
print

# setting up scheduled tasks command
SchTasks = "cmd.exe /C schtasks /query /fo LIST /v"

# logging scheduled tasks
with open('scheduled_tasks.txt', 'w') as fout:
	subprocess.call(SchTasks, stdout=fout)

# moving scheduled task information to case folder
os.rename(os.path.realpath('.') + "/" + "scheduled_tasks.txt", CaseFolder + "/LiveResponseData/PersistenceMechanisms" + "/" + "scheduled_tasks.txt")

print "\t" + "[-] Logging loaded processes and DLLs..."
print

# setting up tasklist to log running processes
RunningProcs = "cmd.exe /C tasklist /V"

# logging all running processes
with open('Running_processes.txt', 'w') as fout:
	subprocess.call(RunningProcs, stdout=fout)

# moving running process list to case folder
os.rename(os.path.realpath('.') + "/" + "Running_processes.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Running_processes.txt")

if debugMode == "off":
    # setting up tasklist to log loaded DLLs
    LoadedDLLs = "cmd.exe /C tasklist /M"
    # logging loaded DLLs
    with open('Loaded_dlls.txt', 'w') as fout:
        subprocess.call(LoadedDLLs, stdout=fout)
    # moving loaded DLL list to case folder
    os.rename(os.path.realpath('.') + "/" + "Loaded_dlls.txt", CaseFolder + "/LiveResponseData/PersistenceMechanisms" + "/" + "Loaded_dlls.txt")
else:
    print "(i) DEBUG MODE: Skipping loaded DLLs..."
    print
# setting up tasklist to collect process services
ProcSVC = "cmd.exe /C tasklist /SVC"

# logging scheduled tasks
with open('services_aw_processes.txt', 'w') as fout:
	subprocess.call(ProcSVC, stdout=fout)

# moving scheduled task information to case folder
os.rename(os.path.realpath('.') + "/" + "services_aw_processes.txt", CaseFolder + "/LiveResponseData/PersistenceMechanisms" + "/" + "services_aw_processes.txt")

print "\t" + "[-] Logging IP config information..."
print

# setting up command to grab network config information
IpCfg = "cmd.exe /C ipconfig /all"

# logging network config information
with open('Internet_settings.txt', 'w') as fout:
	subprocess.call(IpCfg, stdout=fout)

# moving network config info to case folder
os.rename(os.path.realpath('.') + "/" + "Internet_settings.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "Internet_settings.txt")

print "\t" + "[-] Recording open network connections..."
print

# setting up command record open network connections
OpenNet = "cmd.exe /C netstat -ano"

# logging open network connection info
with open('Open_network_connections.txt', 'w') as fout:
	subprocess.call(OpenNet, stdout=fout)

# moving open network connection info to case folder
os.rename(os.path.realpath('.') + "/" + "Open_network_connections.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "Open_network_connections.txt")

print "\t" + "[-] Logging DNS cache entries..."
print

# setting up command to log DNS cache
DnsCache = "cmd.exe /C ipconfig /displaydns"

# logging DNS cache
with open('DNS_cache.txt', 'w') as fout:
	subprocess.call(DnsCache, stdout=fout)

# moving log DNS cache info to case folder
os.rename(os.path.realpath('.') + "/" + "DNS_cache.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "DNS_cache.txt")

print "\t" + "[-] Dumping ARP table..."
print

# setting up command to dump ARP table
ArpDump = "cmd.exe /C arp -a"

# dumping ARP table
with open('ARP.txt', 'w') as fout:
	subprocess.call(ArpDump, stdout=fout)

# moving ARP table data to case folder
os.rename(os.path.realpath('.') + "/" + "ARP.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "ARP.txt")

print "\t" + "[-] Logging local user account names..."
print

# setting up command to log local users
LUsers = "cmd.exe /C net user"

# recording local users
with open('List_users.txt', 'w') as fout:
	subprocess.call(LUsers, stdout=fout)

# moving local user list to case folder
os.rename(os.path.realpath('.') + "/" + "List_users.txt", CaseFolder + "/LiveResponseData/UserInfo" + "/" + "List_users.txt")

print "\t" + "[-] Recording network routing information..."
print

# setting up command collect network routing information
NetRouteInfo = "cmd.exe /C netstat -rn"

# collecting network routing information
with open('routing_table.txt', 'w') as fout:
	subprocess.call(NetRouteInfo, stdout=fout)

# moving network routing information to case folder
os.rename(os.path.realpath('.') + "/" + "routing_table.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "routing_table.txt")

print "\t" + "[-] Gathering NetBIOS information... "
print

# setting up nbtstat command
NetBIOSinfo = "cmd.exe /C nbtstat -c"

# collecting netbios info
with open('nbtstat.txt', 'w') as fout:
	subprocess.call(NetBIOSinfo, stdout=fout)

# moving netbios info to case folder
os.rename(os.path.realpath('.') + "/" + "nbtstat.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "nbtstat.txt")

# setting nbtstat sessions command
NetBIOSSess1 = "cmd.exe /C nbtstat -S"

# setting up net sessions command
NetBIOSSess2 = "cmd.exe /C net sessions"

# collecting netbios sessions information
with open('NetBIOS_sessions.txt', 'w') as fout:
	subprocess.call(NetBIOSSess1, stdout=fout)
	subprocess.call(NetBIOSSess2, stdout=fout)

# moving netbios session info to case folders
os.rename(os.path.realpath('.') + "/" + "NetBIOS_sessions.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "NetBIOS_sessions.txt")

# setting up net command to look for files transferred over netbios
NetBIOSXfr = "cmd.exe /C net file"

# loggings any files transfered over netbios
with open('NetBIOS_transferred_files.txt', 'w') as fout:
	subprocess.call(NetBIOSXfr, stdout=fout)

# moving netbios info to case folder
os.rename(os.path.realpath('.') + "/" + "NetBIOS_transferred_files.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "NetBIOS_transferred_files.txt")

print "[+] Gather additional volatile data..."
print
# [END] Additional Volatile Data Gathering

# [BEGIN] Network Data Gathering

print "\t" + "[-] Collecting currently open TCP/UDP ports..."

# Detecting system architecture
if OSArch == 64:
	Cports64Dir = os.path.realpath('.') + "/cports-x64/"
	# setting up variables to run cports with output parameters
	Cports64Run = Cports64Dir + "cports.exe /shtml cports.html /sort 1 /sort ~'Remote Address'"
	Cports64Param = CaseFolder + "/LiveResponseData/NetworkInfo" + "/cports.html"
	Cports64EXE = Cports64Run + Cports64Param
	# executing cports
	subprocess.call(Cports64EXE)

else:
	CportsDir = os.path.realpath('.') + "/cports/"
	# setting up variables to run cports with output parameters
	CportsRun = CportsDir + "cports.exe /shtml cports.html /sort 1 /sort ~'Remote Address'"
	CportsParam = CaseFolder + "/LiveResponseData/NetworkInfo" + "/cports.html"
	CportsEXE = CportsRun + CportsParam
	# executing cports
	subprocess.call(CportsEXE)

# moving cports output case folder
os.rename(os.path.realpath('.') + "/" + "cports.html", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "cports.html")

# [END] Network Data Gathering

# [BEGIN] System Data Gathering
print
print "[+] Gather system data..."
print

def WMIC():
	if OSArch == 64:
		print "\t" + "[-] Detecting OS and System Architecture... [64bit system]"
		print
		print "\t" + "[-] Logging installed software through WMIC..."
		print
        # setting up path to WMIC x64 version
		WMICx64Dir = os.path.realpath('.') + "\\WMIC\\"
		# setting up path to WMIC EXE
		WMICx64ExePath = WMICx64Dir + "WMIC.exe"
		# setting parameters
		WMICx64Param = " /output:'%s\LiveResponseData\BasicInfo\Installed_software_wmic.txt' product get Name, Version" % (CaseFolder)
		# setting WMICx64 execution command
		WMICx64Exec = WMICx64ExePath + WMICx64Param
		subprocess.call(WMICx64Exec)
	else:
		print "\t" + "[-] Detecting OS and System Architecture... [32bit system]"
		print
		print "\t" + "[-] Logging installed software through WMIC..."
		print
		# setting up path to WMICx86 version
		WMICx86Dir = os.path.realpath('.') + "\\WMIC32\\"
		# setting up path to WMIC EXE
		WMICx86ExePath = WMICx86Dir + "WMIC.exe"
		# setting parameters
		WMICx86Param = " /output:'%s\LiveResponseData\BasicInfo\Installed_software_wmic.txt' product get Name, Version" % (CaseFolder)
		# setting WMICx86 execution command
		WMICx86Exec = WMICx86ExePath + WMICx86Param
		subprocess.call(WMICx86Exec)
WMIC()

print
print
print "[+] Run Sysinternals tools..."
print
print "\t" + "[-] Accepting EULA..."
print

# setting up commands to register EULAs for the SI toolset
EULA1 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\Autoruns /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA2 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\PsFile /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA3 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\PsInfo /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA4 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\PsList /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA5 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\PsLoggedOn /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA6 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\PsLogList /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA7 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\Tcpvcon /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA8 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\TCPView /v EulaAccepted /t REG_DWORD /d 1 /f"
EULA9 = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\Streams /v EulaAccepted /t REG_DWORD /d 1 /f"

# adding EULA acceptance to the registry
subprocess.call(EULA1)
subprocess.call(EULA2)
subprocess.call(EULA3)
subprocess.call(EULA4)
subprocess.call(EULA5)
subprocess.call(EULA6)
subprocess.call(EULA7)
subprocess.call(EULA8)
subprocess.call(EULA9)

print

# [autorunsc] setting up path to Sysinternals tools
SiDir = os.path.realpath('.') + "\\sysinternals\\"

# [autorunsc] setting up path to EXE
SiAutorunscEXEPath = SiDir + "autorunsc.exe"

# [autorunsc] running
with open('autorunsc.txt', 'w') as fout:
   subprocess.call(SiAutorunscEXEPath, stdout=fout)

# [autorunsc] moving output to case folder
os.rename(os.path.realpath('.') + "/" + "autorunsc.txt", CaseFolder + "/LiveResponseData/PersistenceMechanisms" + "/" + "autorunsc.txt")

# [psfile] setting up path to EXE
SiPsfileEXEPath = SiDir + "psfile.exe"

# [psfile] running
with open('psfile.txt', 'w') as fout:
   subprocess.call(SiPsfileEXEPath, stdout=fout)

# [psfile] moving output to case folder
os.rename(os.path.realpath('.') + "/" + "psfile.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "psfile.txt")

# [psinfo] setting up path to EXE
SiPsinfoEXEPath = SiDir + "psinfo.exe"

# [psinfo] running
with open('psinfo.txt', 'w') as fout:
   subprocess.call(SiPsinfoEXEPath, stdout=fout)

# [psinfo] moving output to case folder
os.rename(os.path.realpath('.') + "/" + "psinfo.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "psinfo.txt")

# [pslist] setting up path to EXE
SiPslistEXEPath = SiDir + "pslist.exe"

# [pslist] running
with open('pslist.txt', 'w') as fout:
   subprocess.call(SiPslistEXEPath, stdout=fout)

# [pslist] moving output to case folder
os.rename(os.path.realpath('.') + "/" + "pslist.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "pslist.txt")

# [PsLoggedon] setting up path to EXE
SiPsLoggedonEXEPath = SiDir + "PsLoggedon.exe"

# [PsLoggedon] running
with open('PsLoggedon.txt', 'w') as fout:
   subprocess.call(SiPsLoggedonEXEPath, stdout=fout)

# [PsLoggedon] moving output to case folder
os.rename(os.path.realpath('.') + "/" + "PsLoggedon.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "PsLoggedon.txt")

# [psloglist] setting up path to EXE
siPsloglistEXEPath = SiDir + "psloglist.exe"

siPsloglistAppEvtList = "104,1022,1033"
siPsloglistSecEvtList = "1102,4624,4625,4648,4698,4697,4732,4778,4779"
siPsloglistSysEvtLIst = "6,7035,7045"

# 104 - This event indicates that an admin or an application has cleared the specified event log. (App)
# 1022 - New MSI file installed. (App)
# 1033 - Program installed using MsiInstaller. (App)
# 1102 - Event 1102 is logged whenever the Security log is cleared, REGARDLESS of the status of the Audit System Events audit policy. (App)
# 4624 - successful logon (Sec)
# 4625 - failed logon (Sec)
# 4648 - RunAs usage, privilege escalation, lateral movement(Sec)
# 4698 - scheduled task creation, persistence (Sec)
# 4697 - service creation, details will contain "psexec" if used, persistence (Sec)
# 4732 - User added to privileged local group(Sec)
# 4778 - an RDP session was reconnected as opposed to a fresh logon seen by event 4624.(Sec)
# 4779 - an RDP session was disconnected as opposed to a logoff seen by events 4647 or 4634.(Sec)
# 6 - New Kernel Filter Driver. Could be an indication that a kernel-mode rootkit was installed. (Sys)
# 7035 - Successful start OR stop control was sent to a service. (Sys)
# 7045 - New Windows service was installed. (Sys)

# [psloglist] setting parameters
siPsloglistAppParam = " -s -x -i %s application" % (siPsloglistAppEvtList)
siPsloglistSecParam = " -s -x -i %s security" % (siPsloglistSecEvtList)
siPsloglistSysParam = " -s -x -i %s system" % (siPsloglistSysEvtLIst)

# [psloglist] setting execution command
siPsloglistAppExec = siPsloglistEXEPath + siPsloglistAppParam
siPsloglistSecExec = siPsloglistEXEPath + siPsloglistSecParam
siPsloglistSysExec = siPsloglistEXEPath + siPsloglistSysParam

# [psloglist] running
with open('eventlogs.csv', 'w') as fout:
   subprocess.call(siPsloglistAppExec, stdout=fout)
   subprocess.call(siPsloglistSecExec, stdout=fout)
   subprocess.call(siPsloglistSysExec, stdout=fout)

# [psloglist] moving output to case folder
os.rename(os.path.realpath('.') + "/" + "eventlogs.csv", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "eventlogs.csv")

if debugMode == "off":
	# [Tcpvcon] setting up path to EXE
	SiTcpvconEXEPath = SiDir + "Tcpvcon.exe"

	# [Tcpvcon] setting parameters
	SiTcpvconParam = " -a"

	# [Tcpvcon] setting execution command
	SiTcpvconExec = SiTcpvconEXEPath + SiTcpvconParam

	# [Tcpvcon] running
	with open('Tcpvcon.txt', 'w') as fout:
	   subprocess.call(SiTcpvconExec, stdout=fout)

	# [Tcpvcon] moving  output to case folder
	os.rename(os.path.realpath('.') + "/" + "Tcpvcon.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "Tcpvcon.txt")
else:
    print "(i) DEBUG MODE: Skipping network info gathering..."

print
print "[+] Checking WINDIR for alternate data streams..."
print

# [streams] setting up path to EXE
SiStreamsEXEPath = SiDir + "streams.exe"

# [streams] setting parameters
#SiStreamsParam = " -s %s\ | findstr /r /c:'.:' /c:':DATA' | findstr /v /c:'Error opening'" % (os.getenv('WINDIR'))
SiStreamsParam = " -s %s\ " % (os.getenv('WINDIR'))

# [streams] setting execution command
SiStreamsExec = SiStreamsEXEPath + SiStreamsParam

# [streams] running
with open('Alternate_data_streams.txt', 'w') as fout:
   subprocess.call(SiStreamsExec, stdout=fout)

# [streams] moving  output to case folder
os.rename(os.path.realpath('.') + "/" + "Alternate_data_streams.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Alternate_data_streams.txt")

print "\t" + "[-] Removing EULA acceptance..."
print

# setting up commands to remote EULA acceptances for the SI toolset from the registry
EULADel = "cmd.exe /C reg.exe DELETE HKCU\Software\Sysinternals /f"

# removing EULA acceptance from the registry
subprocess.call(EULADel)

# [END] System Data Gathering

# [BEGIN] Prefetch Parsing

print
print
print "[+] Parsing prefetch data..."
print

# [pf] setting up path to TZWorks tools
TZWDir = os.path.realpath('.') + "\\TZWorks\\"

# [pf] setting up path to EXE
PfEXEPath = TZWDir + "pf.exe"

# [pf] setting parameters
PfParams = " -v > %s\LiveResponseData\UserInfo\prefetch-out.txt" % (CaseFolder)

# [pf] dir listing of .pf files collected earlier to pipe into pf.exe
PfFileList = "cmd.exe /C dir %s\LiveResponseData\Prefetch\*.pf /b /s" % (CaseFolder)

# [pf] setting full pf.exe command with args
PfCommand = PfEXEPath + PfParams

# [pf] redirecting .pf file dir list into pf.exe for parsing
PfRun = "%s | %s" % (PfFileList, PfCommand)

# executing the pf command string
subprocess.call(PfRun)

# [END] Prefetch Parsing

# [BEGIN] Registry Extraction
print
print "[+] Dumping registry hives..."
print

# setting up commands to extract registry hives
RegSystem = "cmd.exe /C reg.exe SAVE HKLM\SYSTEM"
RegSoftware = "cmd.exe /C reg.exe SAVE HKLM\SOFTWARE"
RegSAM = "cmd.exe /C reg.exe SAVE HKLM\SAM"
RegSecurity = "cmd.exe /C reg.exe SAVE HKLM\SECURITY"
RegNTUser = "cmd.exe /C reg.exe SAVE HKCU"

# setting up output paths
RegSystemOut = " %s\LiveResponseData\Registry\SYSTEM SYSTEM.hiv" % (CaseFolder)
RegSoftwareOut = " %s\LiveResponseData\Registry\SOFTWARE SOFTWARE.hiv" % (CaseFolder)
RegSAMOut = " %s\LiveResponseData\Registry\SAM SAM.hiv" % (CaseFolder)
RegSecurityOut = " %s\LiveResponseData\Registry\SECURITY SECURITY.hiv" % (CaseFolder)
RegUserOut = " %s\LiveResponseData\Registry\NTUSER NTUSER.hiv" % (CaseFolder)

# setting execution string
RegSystemDump = RegSystem + RegSystemOut
RegSoftwareDump = RegSoftware + RegSoftwareOut
RegSAMDump = RegSAM + RegSAMOut
RegSecurityDump = RegSecurity + RegSecurityOut
RegUserDump = RegNTUser + RegUserOut

# dumping the registry hives
subprocess.call(RegSystemDump)
subprocess.call(RegSoftwareDump)
subprocess.call(RegSAMDump)
subprocess.call(RegSecurityDump)
subprocess.call(RegUserDump)

print
print

# [END] Registry Extraction

# [BEGIN] Registry Parsing
print
print "[+] Parsing registry hives..."
print

# [Regripper] setting up path to Regripper
RrDir = os.path.realpath('.') + "\\regripper\\"

# [Regripper] setting up path to EXE
RrEXEPath = RrDir + "rip.exe"
#RrPlugins = RrDir + "plugins\\"

# [Regripper] setting parameters
RrNtuserParam1 = " -r %s\LiveResponseData\Registry\NTUSER -f " % (CaseFolder)
RrNtuserParam2 = "ntuser"
RrNtuserParam = RrNtuserParam1 + RrNtuserParam2
RrSamParam1 = " -r %s\LiveResponseData\Registry\SAM -f " % (CaseFolder)
RrSamParam2 = "sam"
RrSamParam = RrSamParam1 + RrSamParam2
RrSystemParam1 = " -r %s\LiveResponseData\Registry\SYSTEM -f " % (CaseFolder)
RrSystemParam2 = "SYSTEM"
RrSystemParam = RrSystemParam1 + RrSystemParam2
RrSecurityParam1 = " -r %s\LiveResponseData\Registry\SECURITY -f " % (CaseFolder)
RrSecurityParam2 = "SECURITY"
RrSecurityParam = RrSecurityParam1 + RrSecurityParam2
RrSoftwareParam1 = " -r %s\LiveResponseData\Registry\SOFTWARE -f " % (CaseFolder)
RrSoftwareParam2 = "SOFTWARE"
RrSoftwareParam = RrSoftwareParam1 + RrSoftwareParam2

# [Regripper] setting execution command
RrNtuserExec = RrEXEPath + RrNtuserParam
RrSamExec = RrEXEPath + RrSamParam
RrSystemExec = RrEXEPath + RrSystemParam
RrSecurityExec = RrEXEPath + RrSecurityParam
RrSoftwareExec = RrEXEPath + RrSoftwareParam

# [Regripper] running and logging output
with open('rr.ntuser-out.txt', 'w') as fout:
   subprocess.call(RrNtuserExec, stdout=fout)

with open('rr.sam-out.txt', 'w') as fout:
   subprocess.call(RrSamExec, stdout=fout)

with open('rr.system-out.txt', 'w') as fout:
   subprocess.call(RrSystemExec, stdout=fout)

with open('rr.security-out.txt', 'w') as fout:
   subprocess.call(RrSecurityExec, stdout=fout)

with open('rr.software-out.txt', 'w') as fout:
   subprocess.call(RrSoftwareExec, stdout=fout)


print "!!!!!! THIS IS THE PATH THAT IS BEING CHECKED FOR THE REGRIPPER FILES... DOES IT LOOK RIGHT???"
print
print os.path.realpath('.') + "/" + "rr.ntuser-out.txt", CaseFolder + "/LiveResponseData/Registry/regripped-out" + "/" + "rr.ntuser-out.txt"

# [Regripper] moving output to case folder
os.rename(os.path.realpath('.') + "/" + "rr.ntuser-out.txt", CaseFolder + "/LiveResponseData/Registry/regripped-out" + "/" + "rr.ntuser-out.txt")
os.rename(os.path.realpath('.') + "/" + "rr.sam-out.txt", CaseFolder + "/LiveResponseData/Registry/regripped-out" + "/" + "rr.sam-out.txt")
os.rename(os.path.realpath('.') + "/" + "rr.system-out.txt", CaseFolder + "/LiveResponseData/Registry/regripped-out" + "/" + "rr.system-out.txt")
os.rename(os.path.realpath('.') + "/" + "rr.security-out.txt", CaseFolder + "/LiveResponseData/Registry/regripped-out" + "/" + "rr.security-out.txt")
os.rename(os.path.realpath('.') + "/" + "rr.software-out.txt", CaseFolder + "/LiveResponseData/Registry/regripped-out" + "/" + "rr.software-out.txt")

print
print

# [END] Registry Parsing

# [BEGIN] USB Artifact Parsing
print
print "[+] Grabbing more USB artifacts..."
print

# Detecting system architecture
if os.path.exists("c:\windows\system32\\"):
	# variable to point to the location of "xcopy" on the remote system
	XcopyDir = "c:\windows\system32\\"
	# setting up variables to run xcopy with appropriate parameters
	XcopyParam = XcopyDir + "xcopy.exe /k C:\Windows\inf\setupapi.dev.log "
	XcopyOut = CaseFolder + "\LiveResponseData\Registry\usb-install-log"
	XcopyUsb = XcopyParam + XcopyOut

	# copying USB setup log from target
	subprocess.call(XcopyUsb)

else:
	print
	print "Xcopy missing from target"


# [END] USB Artifact Parsing

# [BEGIN] Hashing all Collected Triage Data
print
print
print "[+] Hashing collected triage data..."
print

# Detecting system architecture
if OSArch == 64:
	# variable to point to the "md5deep-4.4" subdir of current directory
	MD564Path = "%s\md5deep-4.4\md5deep64.exe" % (os.path.realpath('.'))
	# setting up MD5 hashing parameters for collected files
	MD564Param = " -rect %s\* " % (CaseFolder)
	MD564Run = MD564Path + MD564Param
	# variable to point to the "md5deep-4.4" subdir of current directory
	SHA25664Path = "%s\md5deep-4.4\sha256deep64.exe" % (os.path.realpath('.'))
	# setting up MD5 hashing parameters for collected files
	SHA25664Param = " -rect %s\* " % (CaseFolder)
	SHA25664Run = SHA25664Path + SHA25664Param
	# hashing data
	with open('Triage_File_Collection_Hashlist.csv', 'w') as fout:
		subprocess.call(MD564Run, stdout=fout)
#		subprocess.call(SHA25664Run, stdout=fout)
	# moving hash data to case folder
	os.rename(os.path.realpath('.') + "/" + "Triage_File_Collection_Hashlist.csv", CaseFolder + "/" + "Triage_File_Collection_Hashlist.csv")

else:

	# variable to point to the "md5deep-4.4" subdir of current directory
	MD5Path = "%s\md5deep-4.4\md5deep.exe" % (os.path.realpath('.'))
	# setting up MD5 hashing parameters for collected files
	MD5Param = " -rect %s\* " % (CaseFolder)
	MD5Run = MD5Path + MD5Param
	# variable to point to the "md5deep-4.4" subdir of current directory
	SHA256Path = "%s\md5deep-4.4\sha256deep.exe" % (os.path.realpath('.'))
	# setting up MD5 hashing parameters for collected files
	SHA256Param = " -rect %s\* " % (CaseFolder)
	SHA256Run = SHA256Path + SHA256Param
	# hashing data
	with open('Triage_File_Collection_Hashlist.csv', 'w') as fout:
		subprocess.call(MD5Run, stdout=fout)
#		subprocess.call(SHA256Run, stdout=fout)
	# moving hash data to case folder
	os.rename(os.path.realpath('.') + "/" + "Triage_File_Collection_Hashlist.csv", CaseFolder + "/" + "Triage_File_Collection_Hashlist.csv")

# [END] Hashing all Collected Triage Data

print "[+] Cleaning up Triage environment..."
print

shutil.rmtree("%s\cports" % (os.path.realpath('.')))
shutil.rmtree("%s\cports-x64" % (os.path.realpath('.')))
shutil.rmtree("%s\lastactivityview" % (os.path.realpath('.')))
shutil.rmtree("%s\md5deep-4.4" % (os.path.realpath('.')))
shutil.rmtree("%s\PrcView" % (os.path.realpath('.')))
shutil.rmtree("%s\sysinternals" % (os.path.realpath('.')))
shutil.rmtree("%s\TZWorks" % (os.path.realpath('.')))
shutil.rmtree("%s\winutils" % (os.path.realpath('.')))
shutil.rmtree("%s\WMIC" % (os.path.realpath('.')))
shutil.rmtree("%s\WMIC32" % (os.path.realpath('.')))
shutil.rmtree("%s\\xcopy" % (os.path.realpath('.')))
shutil.rmtree("%s\\xcopy64" % (os.path.realpath('.')))
shutil.rmtree("%s\memory" % (os.path.realpath('.')))
shutil.rmtree("%s\\regripper" % (os.path.realpath('.')))

if os.path.exists("DFIRTriage must be ran as Local ADMIN.txt"):
    os.remove("%s\DFIRTriage must be ran as Local ADMIN.txt" % (os.path.realpath('.')))

if os.path.exists("0"):
    os.remove("0")
	
if os.path.exists("1"):
    os.remove("1")

print "#######################################################"
print "#                                                     #"
print "#  (     (    (   (                                   #"
print "#  )\ )  )\ ) )\ ))\ )    *   )                       #"
print "# (()/( (()/((()/(()/(  ` )  /((  (     ) (  (    (   #"
print "#  /(_)) /(_))/(_))(_))  ( )(_))( )\ ( /( )\))(  ))\  #"
print "# (_))_ (_))_(_))(_))   (_(_()|()((_))(_)|(_))\ /((_) #"
print "#  |   \| |_ |_ _| _ \  |_   _|((_|_|(_)_ (()(_|_))   #"
print "#  | |) | __| | ||   /    | | | '_| / _` / _` |/ -_)  #"
print "#  |___/|_|  |___|_|_\    |_| |_| |_\__,_\__, |\___|  #"
print "#                                        |___/        #"
print "#                  Version 2.4.1                      #"
print "#                                                     #"
print "#######################################################"
print
print "[*] DFIRTriage process is now complete. \n\n::::::::::::::::::::::::::::::::::::::::::::::::::::::\n\n Press ENTER to finish. \n\n"
raw_input()
