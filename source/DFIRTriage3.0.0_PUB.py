#! python3

#############################################################################
##                                                                         ##
## Unlicense                                                               ##
## No Copyright                                                            ##
##                                                                         ##
## This is free and unencumbered software released into the public domain. ##
## Anyone is free to copy, modify, publish, use, compile, sell, or         ##
## distribute this software, either in source code form or as a compiled   ##
## binary, for any purpose, commercial or non-commercial, and by any       ##
## means.                                                                  ##
##                                                                         ##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,         ##
## EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF      ##
## MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  ##
## IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR       ##
## OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,   ##
## ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR   ##
## OTHER DEALINGS IN THE SOFTWARE.                                         ##
##                                                                         ##
##  For more information, please refer to  http://unlicense.org            ##
##                                                                         ##
##  Author: Travis Foley, travis.foley@gmail.com                           ##
##          Joel Maisenhelder, dfirtriage@gmail.com                        ##
#############################################################################

#############################################################################
##                                                                         ##
## DESCRIPTION: Forensic acquisition of volatile data and system           ##
## information for use with initial Incident Response.                     ##
##                                                                         ##
## FILENAME: DFIRTriage.py                                                 ##
## VERSION: 3.0                                                            ##
## STATUS: PUBLIC                                                          ##
## NOTE:                                                                   ##
##                                                                         ##
##                                                                         ##
#############################################################################

# Built-in Imports:
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
import getpass


#setup commandline options
parser = argparse.ArgumentParser(description='Forensic acquisition of volatile data and system information for '
                                             'host-based incident response.')
parser.add_argument('-nm', '--nomem', action='store_true', help="Full system collection plus Memory collection")
parser.add_argument('-d', '--debug', action='store_true', help="Debug")
parser.add_argument('-ho', '--hashing', action='store_true', help="Perform hashing ONLY")
parser.add_argument('-bo', '--browserh', action='store_true', help="Perform browser history ONLY")
args = parser.parse_args()

VERSION = "3.1.0"
CURRENTUSER = getpass.getuser()
if args.debug:
    debugMode = 'on'
else:
    debugMode = 'off'

#This is a test to see if we are compiled into a binary or we are just a script
if getattr(sys, 'frozen', False):
    bundle_dir = sys._MEIPASS + "/core.ir/"

else:
    bundle_dir = os.path.dirname(os.path.abspath(__file__)) + "/data"
# Forcing stdout to flush so all print() and stdout.write() functions will display in the console when executing
# over a remote shell with psexec
sys.stdout.flush()
os.system('color 0A')

def HasAdminAccess():
    # Admin rights check ------
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if not is_admin:
        print("\n[+] Has Local Admin rights... [NO]\n")
        open("DFIRTriage must be ran as Local ADMIN.txt", 'w')
        sys.exit(0)
    else:
        print("\n[+] Has Local Admin rights... [Yes]")

def ENV_setup():
    print("\n[+] Setting up environment...\n", flush=True)
    # Exporting tools
    zipFileName = bundle_dir + '\core.ir'
    zipCore = zipfile.ZipFile(zipFileName)
    zipCore.extractall(r'.')
    # Check OS Type
    global OSArch
    global MD5_path
    global CportsDir
    global WMICDir
    global CaseFolder
    global TargetName
    global DateAndTime
    global NOERROR
    global BVHRun
    NOERROR = open(os.devnull, 'w')
    if ('PROGRAMFILES(X86)' in os.environ):
        print("[+] Detecting OS and System Architecture... [64bit system]", flush=True)
        sys.stdout.flush()
        OSArch = 64
        MD5_path = "%s\md5deep-4.4\md5deep64.exe" % (os.path.realpath('.'))
        CportsDir = os.path.realpath('.') + "/cports-x64/"
        WMICDir = os.path.realpath('.') + "\\WMIC\\"
        BVHRun = "BrowsingHistoryView.exe"

    else:
        print("[+] Detecting OS and System Architecture... [32bit system]")
        sys.stdout.flush()
        OSArch = 32
        MD5_path = "%s\md5deep-4.4\md5deep.exe" % (os.path.realpath('.'))
        CportsDir = os.path.realpath('.') + "/cports/"
        WMICDir = os.path.realpath('.') + "\\WMIC32\\"
        BVHRun = "BrowsingHistoryView32.exe"

    # Case Folder

    TargetName = socket.gethostname()
    DateAndTime = time.strftime("%Y%m%d%H%M%S")
    CaseFolder = TargetName + "." + DateAndTime

    print("\n[+] Building acquisition directory structure...\n", flush=True)
    # This list contains list of all directories that need to be created for output
    AppFolders = ["ForensicImages/Memory", "ForensicImages/HDD", "LiveResponseData/BasicInfo", "LiveResponseData/UserInfo",
                  "LiveResponseData/NetworkInfo", "LiveResponseData/PersistenceMechanisms",
                  "LiveResponseData/Registry/regripped-out", "LiveResponseData/Registry/usb-install-log",
                  "LiveResponseData/Prefetch", "LiveResponseData/FileSystem" ]
    if not os.path.exists(CaseFolder):
        os.makedirs(CaseFolder)
    for folder in AppFolders:
        os.makedirs(CaseFolder + "/" + folder)
    pversion = sys.version_info
    pversion_final = ''
    for ver_sec in pversion:
        pversion_final += str(ver_sec) + '.'
    # Capture version and commandline options
    with open('Triage_info.txt', 'w') as fout:
        fout.write('Hostname: ' + TargetName + '\n')
        fout.write('User : ' + CURRENTUSER + '\n')
        fout.write('Time: ' + DateAndTime + '\n')
        fout.write('Version: ' + VERSION + '\n')
        fout.write('Commandline options: ' +str(sys.argv)  + '\n')
        fout.write('Python Version: ' + pversion_final + '\n')

    # moving netstat info to case folder
    os.rename(os.path.realpath('.') + "/" + "Triage_info.txt", CaseFolder + "/"
              "Triage_info.txt")

def ENV_cleanup():
    # [END] Compress and Move Output
    print("[*] DFIRTriage process is now complete. \n\n::::::::::::::::::::::::::::::::::::::::::::::::::::::\n\n"
          "Press ENTER to finish.")
    input()
    print("[+] Cleaning up Triage environment...\n")
    UtilList = ["cports", "cports-x64", "lastactivityview", "md5deep-4.4", "PrcView", "sysinternals", "TZWorks",
                "winutils", "WMIC", "WMIC32", "xcopy", "xcopy64", "memory", "regripper", "BrowsingHistoryView"]

    fileCleanUp = ["DFIRTriage must be ran as Local ADMIN.txt", "0", "1", "2", "3"]
    toolPath = os.path.realpath('.')
    for tool in UtilList:
        shutil.rmtree(toolPath + "\\" + tool)

    for files in fileCleanUp:
        if os.path.exists(files):
            os.remove(files)

    else:
        print("\t[x] Remove everything but the kitchen sink.")
        if os.path.exists("core.ir"):
            os.remove("core.ir")
        #if os.path.exists(__file__):
            #os.remove(__file__)

def Mem_scrap():

    print("[+] Memory acquisition...\n", flush=True)
    # variable to point to the "memory" subdir of current directory
    MemDir = os.path.realpath('.') + "/memory/"

    # setting up variables to run winpemem with different parameters
    MemAcqLoad = MemDir + "winpmem_1.6.2.exe -l"
    MemAcqGet = MemDir + "winpmem_1.6.2.exe memdump.raw"

    # executing winpmem
    subprocess.call(MemAcqLoad, stderr=NOERROR)
    subprocess.call(MemAcqGet, stderr=NOERROR)

    # moving acquired memory image to case folder
    os.rename(os.path.realpath('.') + "/" + "memdump.raw", CaseFolder + "/ForensicImages/Memory" + "/" + "memdump.raw")

def Prefetch():
    print("[+] Prefetch collection...\n", flush=True)


    # Detecting system architecture
    if os.path.exists("c:\windows\system32\\"):
        # variable to point to the location of "xcopy" on the remote system
        XcopyDir = "c:\windows\system32\\"
        # setting up variables to run xcopy with appropriate parameters
        XcopyParam = XcopyDir + "xcopy.exe /s/e/h/i C:\Windows\Prefetch\*.pf "
        XcopyOut = CaseFolder + "\LiveResponseData\Prefetch"
        XcopyPF = XcopyParam + XcopyOut

        # copying prefetch files from target
        subprocess.call(XcopyPF, stdout=NOERROR, stderr=NOERROR)

    else:
        print("\nXcopy missing from target\n", flush=True)

def ListUsers():
    ListStuff = "cmd.exe /C dir c:\\Users /b "
    AllSystemUsers = subprocess.check_output(ListStuff, stderr=NOERROR, universal_newlines=True)
    listOfUsers = AllSystemUsers.rsplit("\n")
    return(listOfUsers)

def Last_user():
    # [BEGIN] Begin LastUser Activity Data Collection
    print("[+] Last User Activity collection...\n", flush=True)

    # variable to point to the "lastactivityview" subdir of current directory
    LAVDir = os.path.realpath('.') + "/lastactivityview/"

    # setting up variables to run LastActivityView with output parameters
    LAVRun = LAVDir + "LastActivityView.exe /shtml "
    LAVParam = CaseFolder + "/LiveResponseData/BasicInfo" + "/LastActivityView.html"
    LAVExe = LAVRun + LAVParam

    # executing lastactivityview
    subprocess.call(LAVExe)

def Hashing_new(output, source_dir):
    print("[+] Hash " + source_dir + "\n", flush=True)
    MD5Param = " -oe -u -t -r " + source_dir
    MD5Run = MD5_path + MD5Param
    #print(MD5Run)
    with open(CaseFolder + "/" + output, 'w') as fout:
        subprocess.call(MD5Run, stdout=fout, stderr=NOERROR)

def Hash_dir(output, source_dir):
    print("[+] Hash " + source_dir + "\n", flush=True)
    SHA256Param = " -rect " + CaseFolder + "\* "
    SHA256Run = MD5_path + SHA256Param
    with open(CaseFolder + "/" + output, 'w') as fout:
        subprocess.call(SHA256Run, stdout=fout)

def CoreIntegrity():
    if os.path.isfile(bundle_dir + "\core.ir"):
        print("\n[+] Verifying core integrity...", flush=True)

    else:
        os.system('color 4F')
        print("\n[!] The DFIRTriage package is incomplete. Please download a new copy.", flush=True)
        sys.exit()

    hasher = hashlib.md5()
    coreVal = "11cbcdf165ae033b8ae4199ae27908a2" \
              ""
    with open(bundle_dir + '\core.ir', 'rb') as corefile:
        buf = corefile.read()
        hasher.update(buf)

    coreCheck = hasher.hexdigest()

    if (coreVal == coreCheck):
        print("\n[+] Core integrity... [OK]", flush=True)

    else:
        os.system('color 4F')
        print("\n[!] Hash values do not match. Integrity check failed. Please download a new copy.", flush=True)
        sys.exit()

def Banner():
    print("\n#######################################################")
    print("#                                                     #")
    print("#  (     (    (   (                                   #")
    print("#  )\ )  )\ ) )\ ))\ )    *   )                       #")
    print("# (()/( (()/((()/(()/(  ` )  /((  (     ) (  (    (   #")
    print("#  /(_)) /(_))/(_))(_))  ( )(_))( )\ ( /( )\))(  ))\  #")
    print("# (_))_ (_))_(_))(_))   (_(_()|()((_))(_)|(_))\ /((_) #")
    print("#  |   \| |_ |_ _| _ \  |_   _|((_|_|(_)_ (()(_|_))   #")
    print("#  | |) | __| | ||   /    | | | '_| / _` / _` |/ -_)  #")
    print("#  |___/|_|  |___|_|_\    |_| |_| |_\__,_\__, |\___|  #")
    print("#                                        |___/        #")
    print("#                    Version %s                    #" % VERSION)
    print("#                                                     #")
    print("#######################################################\n")



def NetworkInfoGathering():
    print("[+] Network information gathering...", flush=True)

    # setting up netstat and parameters
    NetStatEXE = "C:\Windows\System32\\NETSTAT.EXE"
    NetStatEXEParams = " -anb"
    NetStatRun = NetStatEXE + NetStatEXEParams

    # running netstat
    with open('netstat_and_nbtstat_results.txt', 'w') as fout:
        subprocess.call(NetStatRun, stdout=fout)

    # moving netstat info to case folder
    os.rename(os.path.realpath('.') + "/" + "netstat_and_nbtstat_results.txt", CaseFolder +
              "/LiveResponseData/NetworkInfo" + "/" + "netstat_and_nbtstat_results.txt")

def VolatileDataGather():
    # [BEGIN] Additional Volatile Data Gathering
    print("\n[+] Gather additional volatile data...", flush=True)
    print("\n\t" + "[-] Collecting extended process list...\n", flush=True)

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
    os.rename(os.path.realpath('.') + "/" + "PrcView_extended_long.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "PrcView_extended_long.txt")
    os.rename(os.path.realpath('.') + "/" + "PrcView_extended.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "PrcView_extended.txt")

    print("\t" + "[-] Collecting Windows character code page info...\n", flush=True)

    # variable to point to the Windows Code Page program under system32
    CHCPcom = "%s\system32\chcp.com" % (os.getenv('WINDIR'))

    # grabbing character code page info
    with open('Windows_codepage.txt', 'w') as fout:
        subprocess.call(CHCPcom, stdout=fout)

    # moving code page info to case folder
    os.rename(os.path.realpath('.') + "/" + "Windows_codepage.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Windows_codepage.txt")

    if debugMode == "off":
        print("\t" + "[-] Creating complete file listing...\n", flush=True)

        # setting up directory list command
        DirFileList = "cmd.exe /C dir C:\* /s/o-d"

        # running directory list
        with open('Full_file_listing.txt', 'w') as fout:
            subprocess.call(DirFileList, stdout=fout, stderr=NOERROR)

        # moving directory list to case folder
        os.rename(os.path.realpath('.') + "/" + "Full_file_listing.txt",
                  CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Full_file_listing.txt")
    else:
        print("(i) DEBUG MODE: Skipping file listing...\n", flush=True)

    print("\t" + "[-] Creating list of hidden directories...\n", flush=True)

    # setting up netstat and parameters
    HiddenDirList = "cmd.exe /C dir /S /B /AHD C:\Windows\*"

    # running netstat
    with open('List_hidden_directories.txt', 'w') as fout:
        subprocess.call(HiddenDirList, stdout=fout)

    # moving code page info to case folder
    os.rename(os.path.realpath('.') + "/" + "List_hidden_directories.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "List_hidden_directories.txt")

    print("\t" + "[-] Logging user information...\n", flush=True)
    # setting up whoami command
    UserInfo = "%s/whoami.exe" % (os.path.realpath('./winutils'))

    # running whoami
    with open('whoami.txt', 'w') as fout:
        subprocess.call(UserInfo, stdout=fout)

    # moving code page info to case folder
    os.rename(os.path.realpath('.') + "/" + "whoami.txt",
              CaseFolder + "/LiveResponseData/UserInfo" + "/" + "whoami.txt")

    print("\t" + "[-] Logging system info...\n", flush=True)
    # setting up Windows version command
    WinVer = "cmd.exe /C ver"

    # running ver
    with open('Windows_Version.txt', 'w') as fout:
        subprocess.call(WinVer, stdout=fout)

    # moving version info to case folder
    os.rename(os.path.realpath('.') + "/" + "Windows_Version.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Windows_Version.txt")

    # setting up systeminfo command
    SysInfo = "cmd.exe /C systeminfo"

    # running systeminfo
    with open('system_info.txt', 'w') as fout:
        subprocess.call(SysInfo, stdout=fout)

    # moving systeminfo output to case folder
    os.rename(os.path.realpath('.') + "/" + "system_info.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "system_info.txt")

    print("\t" + "[-] Recording current date and time...\n", flush=True)
    # setting up date command
    WinDate = "cmd.exe /C date /T"

    # setting up time command
    WinTime = "cmd.exe /C time /T"

    # logging current date and time
    with open('current_date_time.txt', 'w') as fout:
        subprocess.call(WinDate, stdout=fout)
        subprocess.call(WinTime, stdout=fout)

    # moving date/time information to case folder
    os.rename(os.path.realpath('.') + "/" + "current_date_time.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "current_date_time.txt")

    print("\t" + "[-] Logging scheduled tasks...\n", flush=True)

    # setting up scheduled tasks command
    SchTasks = "cmd.exe /C schtasks /query /fo LIST /v"

    # logging scheduled tasks
    with open('scheduled_tasks.txt', 'w') as fout:
        subprocess.call(SchTasks, stdout=fout)

    # moving scheduled task information to case folder
    os.rename(os.path.realpath('.') + "/" + "scheduled_tasks.txt",
              CaseFolder + "/LiveResponseData/PersistenceMechanisms" + "/" + "scheduled_tasks.txt")

    print("\t" + "[-] Logging loaded processes and DLLs...\n", flush=True)

    # setting up tasklist to log running processes
    RunningProcs = "cmd.exe /C tasklist /V"

    # logging all running processes
    with open('Running_processes.txt', 'w') as fout:
        subprocess.call(RunningProcs, stdout=fout)

    # moving running process list to case folder
    os.rename(os.path.realpath('.') + "/" + "Running_processes.txt",
              CaseFolder + "/LiveResponseData/BasicInfo" + "/" + "Running_processes.txt")

    if debugMode == "off":
        # setting up tasklist to log loaded DLLs
        LoadedDLLs = "cmd.exe /C tasklist /M"
        # logging loaded DLLs
        with open('Loaded_dlls.txt', 'w') as fout:
            subprocess.call(LoadedDLLs, stdout=fout)
        # moving loaded DLL list to case folder
        os.rename(os.path.realpath('.') + "/" + "Loaded_dlls.txt",
                  CaseFolder + "/LiveResponseData/PersistenceMechanisms" + "/" + "Loaded_dlls.txt")
    else:
        print("(i) DEBUG MODE: Skipping loaded DLLs...\n", flush=True)
    # setting up tasklist to collect process services
    ProcSVC = "cmd.exe /C tasklist /SVC"

    # logging scheduled tasks
    with open('services_aw_processes.txt', 'w') as fout:
        subprocess.call(ProcSVC, stdout=fout)

    # moving scheduled task information to case folder
    os.rename(os.path.realpath('.') + "/" + "services_aw_processes.txt",
              CaseFolder + "/LiveResponseData/PersistenceMechanisms" + "/" + "services_aw_processes.txt")

    print("\t" + "[-] Logging IP config information...\n", flush=True)

    # setting up command to grab network config information
    IpCfg = "cmd.exe /C ipconfig /all"

    # logging network config information
    with open('Internet_settings.txt', 'w') as fout:
        subprocess.call(IpCfg, stdout=fout)

    # moving network config info to case folder
    os.rename(os.path.realpath('.') + "/" + "Internet_settings.txt",
              CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "Internet_settings.txt")

    print("\t" + "[-] Recording open network connections...\n", flush=True)

    # setting up command record open network connections
    OpenNet = "cmd.exe /C netstat -ano"

    # logging open network connection info
    with open('Open_network_connections.txt', 'w') as fout:
        subprocess.call(OpenNet, stdout=fout)

    # moving open network connection info to case folder
    os.rename(os.path.realpath('.') + "/" + "Open_network_connections.txt",
              CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "Open_network_connections.txt")

    print("\t" + "[-] Logging DNS cache entries...\n", flush=True)

    # setting up command to log DNS cache
    DnsCache = "cmd.exe /C ipconfig /displaydns"

    # logging DNS cache
    with open('DNS_cache.txt', 'w') as fout:
        subprocess.call(DnsCache, stdout=fout)

    # moving log DNS cache info to case folder
    os.rename(os.path.realpath('.') + "/" + "DNS_cache.txt",
              CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "DNS_cache.txt")

    print("\t" + "[-] Dumping ARP table...\n", flush=True)

    # setting up command to dump ARP table
    ArpDump = "cmd.exe /C arp -a"

    # dumping ARP table
    with open('ARP.txt', 'w') as fout:
        subprocess.call(ArpDump, stdout=fout)

    # moving ARP table data to case folder
    os.rename(os.path.realpath('.') + "/" + "ARP.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "ARP.txt")

    print("\t" + "[-] Logging local user account names...\n", flush=True)

    # setting up command to log local users
    LUsers = "cmd.exe /C net user"

    # recording local users
    with open('List_users.txt', 'w') as fout:
        subprocess.call(LUsers, stdout=fout)

    # moving local user list to case folder
    os.rename(os.path.realpath('.') + "/" + "List_users.txt",
              CaseFolder + "/LiveResponseData/UserInfo" + "/" + "List_users.txt")

    print("\t" + "[-] Recording network routing information...\n", flush=True)

    # setting up command collect network routing information
    NetRouteInfo = "cmd.exe /C netstat -rn"

    # collecting network routing information
    with open('routing_table.txt', 'w') as fout:
        subprocess.call(NetRouteInfo, stdout=fout)

    # moving network routing information to case folder
    os.rename(os.path.realpath('.') + "/" + "routing_table.txt",
              CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "routing_table.txt")

    print("\t" + "[-] Gathering NetBIOS information... \n", flush=True)

    # collecting netbios infon

    # setting up net sessions command
    NetBIOSSess2 = "cmd.exe /C net sessions"

    # collecting netbios sessions information
    with open('NetBIOS_sessions.txt', 'w') as fout:
        subprocess.call(NetBIOSSess2, stdout=fout)

    # moving netbios session info to case folders
    os.rename(os.path.realpath('.') + "/" + "NetBIOS_sessions.txt",
              CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "NetBIOS_sessions.txt")

    # setting up net command to look for files transferred over netbios
    NetBIOSXfr = "cmd.exe /C net file"

    # loggings any files transfered over netbios
    with open('NetBIOS_transferred_files.txt', 'w') as fout:
        subprocess.call(NetBIOSXfr, stdout=fout)

    # moving netbios info to case folder
    os.rename(os.path.realpath('.') + "/" + "NetBIOS_transferred_files.txt",
              CaseFolder + "/LiveResponseData/NetworkInfo" + "/" + "NetBIOS_transferred_files.txt")

    print("[+] Gather additional volatile data...\n", flush=True)

def NetworkDataGathering():
    print("\t" + "[-] Collecting currently open TCP/UDP ports...", flush=True)
    # setting up variables to run cports with output parameters
    CportsRun = CportsDir + "cports.exe /shtml cports.html /sort 1 /sort ~'Remote Address'"
    CportsParam = CaseFolder + "/LiveResponseData/NetworkInfo" + "/cports.html"
    CportsEXE = CportsRun + CportsParam
    # executing cports
    subprocess.call(CportsEXE)
    # moving cports output case folder
    os.rename(os.path.realpath('.') + "/" + "cports.html", CaseFolder +
              "/LiveResponseData/NetworkInfo" + "/" + "cports.html")

def SystemDataGathering():
    # [BEGIN] System Data Gathering
    print("[+] Gather system data...\n", flush=True)
    WMICExePath = WMICDir + "WMIC.exe"
    # setting parameters
    WMICParam = " /output:" + CaseFolder + \
                "\LiveResponseData\BasicInfo\Installed_software_wmic.txt product get Name, Version"
    WMICExec = WMICExePath + WMICParam

    print("[+] Run Sysinternals tools...\n", flush=True)
    print("\t" + "[-] Accepting EULA...\n", flush=True)
    SysInternalsList = ['Autoruns', 'PsFile','PsInfo', 'PsList', 'PsLoggedOn',
                        'PsLogList', 'Tcpvcon', 'TCPView', 'Streams']
    # setting up commands to register EULAs for the SI toolset
    for program in SysInternalsList:
        EULA = "cmd.exe /C reg.exe ADD HKCU\Software\Sysinternals\\" + program + " /v EulaAccepted /t REG_DWORD /d 1 /f"
        subprocess.call(EULA, stdout=NOERROR, stderr=NOERROR)

    # [autorunsc] setting up path to Sysinternals tools
    SiDir = os.path.realpath('.') + "\\sysinternals\\"

    # [autorunsc] setting up path to EXE
    SiAutorunscEXEPath = SiDir + "autorunsc.exe"

    # [autorunsc] running
    print("\t[-] Running...\n", flush=True)
    with open('autorunsc.txt', 'w') as fout:
       subprocess.call(SiAutorunscEXEPath, stdout=fout, stderr=NOERROR)

    # [autorunsc] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "autorunsc.txt", CaseFolder + "/LiveResponseData/PersistenceMechanisms"
              + "/" + "autorunsc.txt")

    # [psfile] setting up path to EXE
    SiPsfileEXEPath = SiDir + "psfile.exe"

    # [psfile] running
    with open('psfile.txt', 'w') as fout:
       subprocess.call(SiPsfileEXEPath, stdout=fout, stderr=NOERROR)

    # [psfile] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "psfile.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/"
              + "psfile.txt")

    # [psinfo] setting up path to EXE
    SiPsinfoEXEPath = SiDir + "psinfo.exe"

    # [psinfo] running
    with open('psinfo.txt', 'w') as fout:
       subprocess.call(SiPsinfoEXEPath, stdout=fout, stderr=NOERROR)

    # [psinfo] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "psinfo.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/"
              + "psinfo.txt")

    # [pslist] setting up path to EXE
    SiPslistEXEPath = SiDir + "pslist.exe"

    # [pslist] running
    with open('pslist.txt', 'w') as fout:
       subprocess.call(SiPslistEXEPath, stdout=fout, stderr=NOERROR)

    # [pslist] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "pslist.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/"
              + "pslist.txt")

    # [PsLoggedon] setting up path to EXE
    SiPsLoggedonEXEPath = SiDir + "PsLoggedon.exe"

    # [PsLoggedon] running
    with open('PsLoggedon.txt', 'w') as fout:
       subprocess.call(SiPsLoggedonEXEPath, stdout=fout, stderr=NOERROR)

    # [PsLoggedon] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "PsLoggedon.txt", CaseFolder + "/LiveResponseData/BasicInfo" + "/"
              + "PsLoggedon.txt")

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
       subprocess.call(siPsloglistAppExec, stdout=fout, stderr=NOERROR)
       subprocess.call(siPsloglistSecExec, stdout=fout, stderr=NOERROR)
       subprocess.call(siPsloglistSysExec, stdout=fout, stderr=NOERROR)

    # [psloglist] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "eventlogs.csv", CaseFolder + "/LiveResponseData/BasicInfo" + "/"
              + "eventlogs.csv")

    if debugMode == "off":
        # [Tcpvcon] setting up path to EXE
        SiTcpvconEXEPath = SiDir + "Tcpvcon.exe"

        # [Tcpvcon] setting parameters
        SiTcpvconParam = " -a"

        # [Tcpvcon] setting execution command
        SiTcpvconExec = SiTcpvconEXEPath + SiTcpvconParam

        # [Tcpvcon] running
        with open('Tcpvcon.txt', 'w') as fout:
           subprocess.call(SiTcpvconExec, stdout=fout, stderr=NOERROR)

        # [Tcpvcon] moving  output to case folder
        os.rename(os.path.realpath('.') + "/" + "Tcpvcon.txt", CaseFolder + "/LiveResponseData/NetworkInfo" + "/"
                  + "Tcpvcon.txt")
    else:
        print("(i) DEBUG MODE: Skipping network info gathering...", flush=True)

    print("[+] Checking WINDIR for alternate data streams...\n" , flush=True)

    # [streams] setting up path to EXE
    SiStreamsEXEPath = SiDir + "streams.exe"

    # [streams] setting parameters
    SiStreamsParam = " -s %s\ " % (os.getenv('WINDIR'))

    # [streams] setting execution command
    SiStreamsExec = SiStreamsEXEPath + SiStreamsParam

    # [streams] running
    with open('Alternate_data_streams.txt', 'w') as fout:
        subprocess.call(SiStreamsExec, stdout=fout, stderr=NOERROR)

    # [streams] moving  output to case folder
    os.rename(os.path.realpath('.') + "/" + "Alternate_data_streams.txt", CaseFolder + "/LiveResponseData/BasicInfo"
              + "/" + "Alternate_data_streams.txt")

    print("\t" + "[-] Removing EULA acceptance...", flush=True)

    # setting up commands to remote EULA acceptances for the SI toolset from the registry
    EULADel = "cmd.exe /C reg.exe DELETE HKCU\Software\Sysinternals /f"

    # removing EULA acceptance from the registry
    subprocess.call(EULADel, stdout=NOERROR, stderr=NOERROR)

def PrefetchP():
    # [BEGIN] Prefetch Parsing
    print("\n[+] Parsing prefetch data...\n", flush=True)

    # [pf] setting up path to TZWorks tools
    TZWDir = os.path.realpath('.') + "\\TZWorks\\"

    # [pf] setting up path to EXE
    PfEXEPath = TZWDir + "pf.exe"

    # [pf] setting parameters
    PfParams = " -pipe -v > %s\LiveResponseData\\UserInfo\prefetch-out.txt" % (CaseFolder)

    # [pf] dir listing of .pf files collected earlier to pipe into pf.exe
    PfFileList = "cmd.exe /C dir %s\LiveResponseData\Prefetch\*.pf /b /s" % (CaseFolder)

    # [pf] setting full pf.exe command with args
    PfCommand = PfEXEPath + PfParams

    # [pf] redirecting .pf file dir list into pf.exe for parsing
    PfRun = "%s | %s" % (PfFileList, PfCommand)

    # executing the pf command string
    subprocess.call(PfRun, stderr=NOERROR)

def RegistryStuff():
    # [BEGIN] Registry Extraction
    print("[+] Dumping registry hives...\n", flush=True)
    RegistryDumpHives = {"NTUSER": 'HKCU', "SAM": 'HKLM\SAM', "SYSTEM": 'HKLM\SYSTEM',
                         "SECURITY": 'HKLM\SECURITY', "SOFTWARE": 'HKLM\SOFTWARE'}
    for hive in RegistryDumpHives:
        Reg = "cmd.exe /C reg.exe SAVE " + RegistryDumpHives[hive]
        RegOut = " " + CaseFolder + "\LiveResponseData\Registry\\" + hive + " " + hive + ".hiv"
        RegDump = Reg + RegOut
        subprocess.call(RegDump, stdout=NOERROR, stderr=NOERROR)

    # [END] Registry Extraction

    # [BEGIN] Registry Parsing
    print("[+] Parsing registry hives...\n", flush=True)

    # [Regripper] setting up path to Regripper
    RrDir = os.path.realpath('.') + "\\regripper\\"

    # [Regripper] setting up path to EXE
    RrEXEPath = RrDir + "rip.exe"

    # [Regripper] setting parameters
    RegistryHives = ["NTUSER", "SAM", "SYSTEM", "SECURITY", "SOFTWARE"]
    for hives in RegistryHives:
        Param1 = " -r " + CaseFolder + "\LiveResponseData\Registry\\" + hives + " -f " + hives
        RegExec = RrEXEPath + Param1
        outPutFile = "rr." + hives + "-out.txt"
        with open(outPutFile, 'w') as fout:
            subprocess.call(RegExec, stdout=fout, stderr=NOERROR)
        os.rename(os.path.realpath('.') + "/" + outPutFile, CaseFolder +
                  "/LiveResponseData/Registry/regripped-out" + "/" + outPutFile)

def USBAP():
    # [BEGIN] USB Artifact Parsing
    print("[+] Grabbing more USB artifacts...\n", flush=True)

    # Detecting system architecture
    if os.path.exists("c:\windows\system32\\"):
        # variable to point to the location of "xcopy" on the remote system
        XcopyDir = "c:\windows\system32\\"
        # setting up variables to run xcopy with appropriate parameters
        XcopyParam = XcopyDir + "xcopy.exe C:\Windows\inf\setupapi.dev.log "
        XcopyOut = CaseFolder + "\LiveResponseData\Registry\\usb-install-log"
        XcopyUsb = XcopyParam + XcopyOut

        # copying USB setup log from target
        subprocess.call(XcopyUsb, stdout=NOERROR, stderr=NOERROR)

    else:
        print("Xcopy missing from target", flush=True)

def Data_compress():

    print("[+] Compressing triage output... please wait", flush=True)
    # Compress Case Folder output data
    fileCompress = TargetName + "." + DateAndTime +".zip"
    zf = zipfile.ZipFile(fileCompress, "w", allowZip64=True)
    for dirname, subdirs, files in os.walk(CaseFolder):
        zf.write(dirname)
        for filename in files:
            zf.write(os.path.join(dirname, filename))
    zf.close()
    shutil.rmtree(os.path.realpath(CaseFolder))

def GetBrowserHistory():

    print("[+] Getting User Browsing History...\n", flush=True)
    BHVDir = os.path.realpath('.') + "\\BrowsingHistoryView\\"
    BHVEXEPath = BHVDir + BVHRun
    BHVParam = " /SaveDirect /sort 3 /VisitTimeFilterType 1 /cfg BrowsingHistoryView.cfg /scomma" + " " + CaseFolder \
               + "/LiveResponseData/BasicInfo/BrowsingHistoryView.csv  "
    BHVCommand = BHVEXEPath + BHVParam
    BHVRun = BHVCommand
    subprocess.call(BHVRun, stderr=NOERROR)

########################################################################################################################
#   All function calls should be defined above this.                                                                   #
########################################################################################################################
Banner()
sys.stdout.flush()
HasAdminAccess()
CoreIntegrity()
ENV_setup()

if not args.nomem:
    Mem_scrap()
    print("\n", flush=True)

#Just doing Browser History
if args.browserh:
    GetBrowserHistory()
    Hash_dir('Triage_File_Collection_Hashlist.csv',CaseFolder)
    Data_compress()
    Banner()
    sys.stdout.flush()
    ENV_cleanup()
    sys.exit(0)

if args.hashing:
    Hashing_new("LiveResponseData/BasicInfo/Full_System.txt", "c:\\")
    Hash_dir('Triage_File_Collection_Hashlist.csv',CaseFolder)
    Data_compress()
    Banner()
    sys.stdout.flush()
    ENV_cleanup()
    sys.exit(0)


Prefetch()
Last_user()
UsersList = ListUsers()

#Hash temp dir for all users who have logged onto the system
for user in UsersList:
    Hashing_new('LiveResponseData/BasicInfo/Hashes_md5_' + user + '_TEMP_WindowsPE_and_Dates.txt', 'c:\\Users\\'
                + user + '\AppData\Local\Temp')
    sys.stdout.flush()
Hashing_new('LiveResponseData/BasicInfo/Hashes_md5_System32_WindowsPE_and_Dates.txt', 'c:\\windows\system32')
Hashing_new('LiveResponseData/BasicInfo/Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt', 'c:\\temp')


NetworkInfoGathering()
VolatileDataGather()
SystemDataGathering()
PrefetchP()
RegistryStuff()
USBAP()
GetBrowserHistory()

# [BEGIN] Hashing all Collected Triage Data
print("[+] Hashing collected triage data...\n", flush=True)
Hash_dir('Triage_File_Collection_Hashlist.csv' ,CaseFolder)

Data_compress()
Banner()
sys.stdout.flush()
ENV_cleanup()
sys.exit(0)
