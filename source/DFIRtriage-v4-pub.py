#!/usr/bin/env python
"""Digital forensic acquisition tool for Windows based incident response"""
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
## FILENAME: DFIRtriage.py                                                 ##
## VERSION: 4.0                                                            ##
## STATUS: PUB                                                             ##
## AUTHORS: Travis Foley // Joel Maisenhelder                              ##
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

NOERROR = open(os.devnull, 'w')
TARGETNAME = socket.gethostname()
DATEANDTIME = time.strftime("%Y%m%d%H%M%S")
CASEFOLDER = TARGETNAME + "." + DATEANDTIME
# the amount of free space required to get a full memory image in GB's
MINDISKSPACE = 75
OSARCH = ''
MD5_PATH = ''
CPORTSDIR = ''
WMICDIR = ''
BVHRUN = ''
OSVERSION = sys.getwindowsversion()
if OSVERSION.major == 10:
    LOGGEDUSERS = subprocess.getoutput("query user")
else:
    LOGGEDUSERS = ""

#setup commandline options
PARSER = argparse.ArgumentParser(
    description='Forensic acquisition of volatile data and system information for use '
    'in initial incident response ', epilog='Example usage: "dfirtriage.exe" (runs all) OR "dfirtriage -bho -nm" (pulls browser history only then exits')
PARSER.add_argument('-nm', '--nomem', action='store_true', help="Bypasses memory acquisition")
PARSER.add_argument('-elf', '--evtlogfiles', action='store_true', \
 help="Pulls full APP, SEC, & SYS evtx files then exits")
PARSER.add_argument('-elp', '--evtlogparse', action='store_true',
                    help="Targets only the following events then exits: "
                    "[APP] 104, 1022, 1033    [SEC] 1102, 4624, 4625, 4634,"
                    "4647, 4672, 4648, 4688, 4697, 4698,  "
                    "4699, 4700, 4701, 4702, 4720, 4722, 4724,"
                    "4728, 4732, 4735, 4738, 4756, 4776, 4778, 4779, 4798, 4799, "
                    "5140, 5145, 7034, 7036, 7040    [SYS] 6,"
                    "104, 7035, 7045    [PWSH] 600, 4105, 4106)")
PARSER.add_argument('-elpa', '--evtlogparseall', action='store_true',
                    help="Parses all Application, System, and Security event log events then exits")
PARSER.add_argument('-ho', '--hashonly', action='store_true', help="Hashes common directories used by malware then exits")
PARSER.add_argument('-bho', '--browserhistonly', action='store_true', help="Pulls browser history only then exits")
PARSER.add_argument('-mo', '--memonly', action='store_true', help="Acquires memory only then exits")
ARGS = PARSER.parse_args()

VERSION = "4.0.0"
CURRENTUSER = getpass.getuser()

#This is a test to see if we are compiled into a binary or we are just a script
if getattr(sys, 'frozen', False):
    BUNDLE_DIR = sys._MEIPASS + "/core.ir/"

else:
    BUNDLE_DIR = os.path.dirname(os.path.abspath(__file__)) + "/data"
# Forcing stdout to flush so all print() and stdout.write()
# functions will display in the console when executing
# over a remote shell with psexec
sys.stdout.flush()
os.system('color 0A')

def has_admin_access():
    """Admin rights check and exit if they are not found """
    try:
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if not is_admin:
        print("\n[+] Has Local Admin rights... [NO]\n")
        open("DFIRTriage must be ran as Local ADMIN.txt", 'w')
        sys.exit(0)
    else:
        print("\n[+] Has Local Admin rights... [YES]")

def env_setup():
    """Setup all the enviroment stuff"""
    print("\n[+] Setting up environment...\n", flush=True)
    # Exporting tools
    zip_file_name = BUNDLE_DIR + '\\core.ir'
    zip_core = zipfile.ZipFile(zip_file_name)
    zip_core.extractall(r'.')
    #Check OS Type
    global OSARCH
    global MD5_PATH
    global CPORTSDIR
    global WMICDIR
    global BVHRUN
    if 'PROGRAMFILES(X86)' in os.environ:
        print("[+] Detecting OS and System Architecture... [64-BIT]", flush=True)
        sys.stdout.flush()
        OSARCH = 64
        MD5_PATH = "{}\\md5deep-4.4\\md5deep64.exe".format(os.path.realpath('.'))
        CPORTSDIR = os.path.realpath('.') + "/cports-x64/"
        WMICDIR = os.path.realpath('.') + "\\WMIC\\"
        BVHRUN = "BrowsingHistoryView.exe"

    else:
        print("[+] Detecting OS and System Architecture... [32bit system]")
        sys.stdout.flush()
        OSARCH = 32
        MD5_PATH = "{}\\md5deep-4.4\\md5deep.exe".format(os.path.realpath('.'))
        CPORTSDIR = os.path.realpath('.') + "/cports/"
        WMICDIR = os.path.realpath('.') + "\\WMIC32\\"
        BVHRUN = "BrowsingHistoryView32.exe"

    print("\n[+] Building acquisition directory structure...\n", flush=True)
    # This list contains list of all directories that need to be created for output
    app_folders = ["ForensicImages/Memory", "ForensicImages/HDD",
                   "LiveResponseData/BasicInfo", "LiveResponseData/UserInfo",
                   "LiveResponseData/EventLogs",
                   "LiveResponseData/NetworkInfo", "LiveResponseData/PersistenceMechanisms",
                   "LiveResponseData/Registry/regripped-out",
                   "LiveResponseData/Registry/usb-install-log",
                   "LiveResponseData/Prefetch", "LiveResponseData/FileSystem"]
    if not os.path.exists(CASEFOLDER):
        os.makedirs(CASEFOLDER)
    for folder in app_folders:
        os.makedirs(CASEFOLDER + "/" + folder)
    pversion = sys.version_info
    pversion_final = ''
    for ver_sec in pversion:
        pversion_final += str(ver_sec) + '.'
    # Capture version and commandline options
    with open('Triage_info.txt', 'w') as fout:
        fout.write('Hostname: ' + TARGETNAME + '\n')
        fout.write('User : ' + CURRENTUSER + '\n')
        fout.write('Time: ' + DATEANDTIME + '\n')
        fout.write('Version: ' + VERSION + '\n')
        fout.write('Commandline options: ' +str(sys.argv)  + '\n')
        fout.write('Python Version: ' + pversion_final + '\n')
        fout.write('Logged in Users: ' + LOGGEDUSERS + '\n')

    # moving triage info file to case folder
    os.rename(os.path.realpath('.') + "/" + "Triage_info.txt", CASEFOLDER + "/"
              "Triage_info.txt")

def env_cleanup():
    """[END] Compress and Move Output"""
    print("[*] DFIRTriage process is now complete."
          "\n\n::::::::::::::::::::::::::::::::::::::::::::::::::::::\n\n"
          "Press ENTER to finish.")
    input()
    print("[+] Cleaning up Triage environment...\n")
    util_list = ["cports", "cports-x64", "lastactivityview", "md5deep-4.4", "PrcView",
                 "sysinternals", "PECmd", "winutils", "WMIC", "WMIC32", "xcopy", "xcopy64",
                 "memory", "regripper", "BrowsingHistoryView"]
    #These are files that need to be cleaned up and not included in the zip
    file_clean_up = ["DFIRTriage must be ran as Local ADMIN.txt", "0", "1", "2", "3"]
    tool_path = os.path.realpath('.')
    for tool in util_list:
        shutil.rmtree(tool_path + "\\" + tool)

    for files in file_clean_up:
        if os.path.exists(files):
            os.remove(files)

    print("\t[x] Remove everything but the kitchen sink.")
    if os.path.isdir("data"):
        os.system("rd /s/q data")
    if os.path.exists(__file__):
        os.remove(__file__)

def mem_scrape():
    """Scrapes the memory from the target system"""
    print("[+] Memory acquisition...\n", flush=True)
    # variable to point to the "memory" subdir of current directory
    mem_dir = os.path.realpath('.') + "\\memory\\"
    # setting up variables to run winpemem with different parameters
    mem_acq_get = mem_dir + "winpmem_3.1.rc10.exe --volume_format raw -o memdump.raw"
    # executing winpmem
    subprocess.call(mem_acq_get, stderr=NOERROR)
    # moving acquired memory image to case folder
    os.rename(os.path.realpath('.') + "\\" + "memdump.raw", CASEFOLDER \
        + "\\ForensicImages\\Memory" + "\\" + "memdump.raw")

def pre_fetch():
    """Collects the Prefetch"""
    print("[+] Prefetch collection...\n", flush=True)

    # Detecting system architecture
    if os.path.exists("c:\\windows\\system32\\"):
        # variable to point to the location of "xcopy" on the remote system
        xcopy_dir = "c:\\windows\\system32\\"
        # setting up variables to run xcopy with appropriate parameters
        xcopy_param = xcopy_dir + "xcopy.exe /s/e/h/i C:\\Windows\\Prefetch\\*.pf "
        xcopy_out = CASEFOLDER + "\\LiveResponseData\\Prefetch"
        xcopy_pf = xcopy_param + xcopy_out

        # copying prefetch files from target
        subprocess.call(xcopy_pf, stdout=NOERROR, stderr=NOERROR)

    else:
        print("\nXcopy missing from target\n", flush=True)

def list_users():
    """Get a list of the users from the system"""
    list_stuff = "cmd.exe /C dir c:\\Users /b "
    all_system_users = subprocess.check_output(list_stuff, stderr=NOERROR, universal_newlines=True)
    list_of_users = all_system_users.rsplit("\n")
    return list_of_users

def last_user():
    """[BEGIN] Begin LastUser Activity Data Collection"""
    print("[+] Last User Activity collection...\n", flush=True)

    # variable to point to the "lastactivityview" subdir of current directory
    lav_dir = os.path.realpath('.') + "/lastactivityview/"

    # setting up variables to run LastActivityView with output parameters
    lav_run = lav_dir + "LastActivityView.exe /shtml "
    lav_param = CASEFOLDER + "/LiveResponseData/BasicInfo" + "/LastActivityView.html"
    lav_exe = lav_run + lav_param

    # executing lastactivityview
    subprocess.call(lav_exe)

def hashing_new(output, source_dir):
    """Hash Files"""
    print("[+] Hash " + source_dir + "\n", flush=True)
    md5_param = " -oe -u -t -r " + source_dir
    md5_run = MD5_PATH + md5_param
    #print(md5_run)
    with open(CASEFOLDER + "/" + output, 'w') as fout:
        subprocess.call(md5_run, stdout=fout, stderr=NOERROR)

def hash_dir(output, source_dir):
    """hash directory"""
    print("[+] Hash " + source_dir + "\n", flush=True)
    sha256_param = " -rect " + CASEFOLDER + "\\LiveResponseData\\* "
    sha256_run = MD5_PATH + sha256_param
    with open(CASEFOLDER + "/" + output, 'w') as fout:
        subprocess.call(sha256_run, stdout=fout)

def banner():
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
    print("#                    Version {}                    #".format(VERSION))
    print("#                                                     #")
    print("#######################################################\n")

def network_info_gathering():
    """Collect out network information"""
    print("[+] Network information gathering...", flush=True)

    # setting up netstat and parameters
    net_stat_exe = "C:\\Windows\\System32\\NETSTAT.EXE"
    net_stat_exe_params = " -anbo"
    net_stat_run = net_stat_exe + net_stat_exe_params

    # running netstat
    with open('netstat_and_nbtstat_results.txt', 'w') as fout:
        subprocess.call(net_stat_run, stdout=fout)

    # moving netstat info to case folder
    os.rename(os.path.realpath('.') + "/" + "netstat_and_nbtstat_results.txt", CASEFOLDER +
              "/LiveResponseData/NetworkInfo" + "/" + "netstat_and_nbtstat_results.txt")

    # grabbing host file
    hosts_file = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    hosts_file_dst = "{}/LiveResponseData/NetworkInfo/{}".format(CASEFOLDER, "hosts.txt")
    shutil.copy(hosts_file, hosts_file_dst)

def volatile_data_gather():
    """Gathers the volatile data"""
    print("\n[+] Gather additional volatile data...\n", flush=True)
    procs = [
        {'Command': "cmd.exe /C tasklist /V", 'output': "Running_processes.txt",
         'outdir': "/BasicInfo/"},
        {'Command': "cmd.exe /C tasklist /M", 'output': "Loaded_dlls.txt",
         'outdir': "/PersistenceMechanisms/"},
        {'Command': "cmd.exe /C tasklist /SVC", 'output': "services_aw_processes.txt",
         'outdir': "/PersistenceMechanisms/"},
        {'Command': "cmd.exe /C ipconfig /all", 'output': "Internet_settings.txt",
         'outdir': "/NetworkInfo/"},
        {'Command': "cmd.exe /C netstat -anbo", 'output': "Open_network_connections.txt",
         'outdir':"/NetworkInfo/"},
        {'Command': "cmd.exe /C ipconfig /displaydns", 'output': "DNS_cache.txt",
         'outdir':"/NetworkInfo/"},
        {'Command': "cmd.exe /C arp -a", 'output': "ARP.txt",
         'outdir':"/NetworkInfo/"},
        {'Command': "cmd.exe /C net user", 'output': "List_users.txt",
         'outdir':"/UserInfo/"},
        {'Command': "cmd.exe /C netstat -rn", 'output': "routing_table.txt",
         'outdir':"/NetworkInfo/"},
        {'Command': "cmd.exe /C net sessions", 'output': "NetBIOS_sessions.txt",
         'outdir':"/NetworkInfo/"},
        {'Command': "cmd.exe /C net file", 'output': "NetBIOS_transferred_files.txt",
         'outdir':"/NetworkInfo/"},
        {'Command': "cmd.exe /C schtasks /query /fo LIST /v", 'output': "scheduled_tasks.txt",
         'outdir':"/PersistenceMechanisms/"},
        {'Command': "cmd.exe /C date /T", 'output': "current_date.txt",
         'outdir':"/BasicInfo/"},
        {'Command': "cmd.exe /C time /T", 'output': "current_time.txt",
         'outdir':"/BasicInfo/"},
        {'Command': "cmd.exe /C systeminfo", 'output': "system_info.txt",
         'outdir':"/BasicInfo/"},
        {'Command': "cmd.exe /C ver", 'output': "Windows_Version.txt",
         'outdir':"/BasicInfo/"},
        {'Command': "cmd.exe /C dir /S /B /AHD C:\\Windows\\*",
         'output': "List_hidden_directories.txt", 'outdir':"/BasicInfo/"},
        {'Command': "cmd.exe /C dir C:\\* /s/o-d", 'output': "Full_file_listing.txt",
         'outdir':"/BasicInfo/"},
        {'Command': "{}\\system32\\chcp.com".format(os.getenv('WINDIR')),
         'output': "Windows_codepage.txt", 'outdir':"/BasicInfo/"},
        {'Command': "{}/whoami.exe".format(os.path.realpath('./winutils')), 'output': "whoami.txt",
         'outdir':"/UserInfo/"}
    ]
    for processes in procs:
        running_procs = processes['Command']
        with open(processes['output'], "w+") as fout:
            subprocess.call(running_procs, stdout=fout)
    for files in procs:
        os.rename(os.path.realpath('.') + "/" + files['output'],
                  CASEFOLDER + "/LiveResponseData" + files['outdir'] + files['output'])

def network_data_gathering():
    """Get open TCP and UDP ports"""
    print("\t" + "[-] Collecting currently open TCP/UDP ports...", flush=True)
    # setting up variables to run cports with output parameters
    c_ports_run = CPORTSDIR + "cports.exe /shtml cports.html /sort 1 /sort ~'Remote Address'"
    c_ports_param = CASEFOLDER + "/LiveResponseData/NetworkInfo" + "/cports.html"
    c_ports_exe = c_ports_run + c_ports_param
    # executing cports
    subprocess.call(c_ports_exe)
    # moving cports output case folder
    os.rename(os.path.realpath('.') + "/" + "cports.html", CASEFOLDER +
              "/LiveResponseData/NetworkInfo" + "/" + "cports.html")

def windows_update_log():
    """Convert ETL files to Windows Update log"""
    winuplog_src = "c:\\users\\{}\\desktop\\windowsupdate.log".format(CURRENTUSER)
    winuplog_dst = CASEFOLDER + "\\LiveResponseData\\BasicInfo\\WindowsUpdate.log"
    print("\n[+] Building Windows Update log from event trace log files...", flush=True)
    os.system("cmd /c powershell Get-WindowsUpdateLog >nul")

    try:
        if os.path.isfile(winuplog_src):
            shutil.move(winuplog_src, winuplog_dst)
        else:
            print("\n[!] Windows Update log was not generated correctly.")
    except IOError  as io_error:
        print(io_error)
        sys.exit("\n[!] Ouch... something went wrong, but I'm not sure what :).")

def powershell_history():
    """Grab powershell console command history file"""
    print("[+] Acquiring existing powershell command history for all users...", flush=True)
    user_list = os.popen("cmd.exe /C dir c:\\Users /b ")
    for users in user_list:
        users = users.strip()
        ps_history_src = "c:\\users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt".format(users)
        ps_history_dst = CASEFOLDER + "\\LiveResponseData\\BasicInfo\\powershell_command_history_{}.txt".format(users)

        try:
            if os.path.isfile(ps_history_src):
                print("\n\t[+] Checking '{}'... [OK].".format(users))
                shutil.copy(ps_history_src, ps_history_dst)
            else:
                print("\n\t[-] Checking '{}'... [NOT FOUND]".format(users))
        except IOError as io_error_2:
            print(io_error_2)
            sys.exit("\n[!] Ouch... something went wrong, but I'm not sure what :).")
    print()

def system_data_gathering():
    """Gather system data"""
    # [BEGIN] System Data Gathering
    print("[+] Gather system data...\n", flush=True)
    print("[+] Run Sysinternals tools...\n", flush=True)
    print("\t[-] Accepting EULA...", flush=True)
    sys_internals_list = ['Autoruns', 'PsFile', 'PsInfo', 'PsList', 'PsLoggedOn',
                          'PsLogList', 'Tcpvcon', 'TCPView', 'Streams']

    for program in sys_internals_list:
        eula = "cmd.exe /C reg.exe ADD HKCU\\Software\\Sysinternals\\" + \
        program + " /v EulaAccepted /t REG_DWORD /d 1 /f"
        subprocess.call(eula, stdout=NOERROR, stderr=NOERROR)

    si_dir = os.path.realpath('.') + "\\sysinternals\\"
    # [autorunsc] setting up path to Sysinternals tools

    sys_proc = [
        {'Command': "autorunsc.exe", 'output': "autorunsc.txt",
         'outdir': "/PersistenceMechanisms/"},
        {'Command': "psfile.exe", 'output': "psfile.txt", 'outdir': "/BasicInfo/"},
        {'Command': "psinfo.exe", 'output': "psinfo.txt", 'outdir': "/BasicInfo/"},
        {'Command': "pslist.exe", 'output': "pslist.txt", 'outdir': "/BasicInfo/"},
        {'Command': "PsLoggedon.exe", 'output': "PsLoggedon.txt", 'outdir':"/BasicInfo/"},
        {'Command': "Tcpvcon.exe -a ", 'output': "Tcpvcon.txt", 'outdir':"/NetworkInfo/"},
        {'Command': "streams.exe  -s {}\\ ".format(os.getenv('WINDIR')),
         'output': "Alternate_data_streams.txt", 'outdir':"/BasicInfo/"}
    ]
    for sys_internals in sys_proc:
        sys_running_procs = si_dir + sys_internals['Command']
        with open(sys_internals['output'], "w+") as fout:
            subprocess.call(sys_running_procs, stdout=fout, stderr=NOERROR)
        os.rename(os.path.realpath('.') + "/" + sys_internals['output'],
                  CASEFOLDER + "/LiveResponseData" + sys_internals['outdir']
                  + sys_internals['output'])

def evtxall():
    """Function to pull full APP, SYS, and SEC event log (evtx) files"""
    print("[+] Grabbing App, Sys, and Sec (.evtx) files...\n", flush=True)
    # Detecting system architecture
    if os.path.exists("c:\\windows\\system32\\"):
        # variable to point to the location of "xcopy" on the remote system
        x_copy_dir = "c:\\windows\\system32\\"
        # setting up variables to run xcopy with appropriate parameters
        x_copy_app_evtx_param = x_copy_dir + "xcopy.exe /s/e/h/i" + "\
         " + x_copy_dir + "\\Winevt\\Logs\\Application.evtx "
        x_copy_sys_evtx_param = x_copy_dir + "xcopy.exe /s/e/h/i" + "\
         " + x_copy_dir + "\\Winevt\\Logs\\System.evtx "
        x_copy_sec_evtx_param = x_copy_dir + "xcopy.exe /s/e/h/i" + "\
         " + x_copy_dir + "\\Winevt\\Logs\\Security.evtx "
        x_copy_evtx_out = CASEFOLDER + "\\LiveResponseData\\EventLogs"
        x_copy_app_evtx = x_copy_app_evtx_param + x_copy_evtx_out

        x_copy_sys_evtx = x_copy_sys_evtx_param + x_copy_evtx_out
        x_copy_sec_evtx = x_copy_sec_evtx_param + x_copy_evtx_out

        # copying Eventlog files from target
        subprocess.call(x_copy_app_evtx, stdout=NOERROR, stderr=NOERROR)
        subprocess.call(x_copy_sys_evtx, stdout=NOERROR, stderr=NOERROR)
        subprocess.call(x_copy_sec_evtx, stdout=NOERROR, stderr=NOERROR)

    else:
        print("\nXcopy missing from target\n", flush=True)

def evtparseall():
    """Function to parse all events in the APP, SEC, & SYS event logs"""
    print("[+] Parsing all events in the APP, SEC, & SYS event logs...\n", flush=True)
    # [psloglist] setting up path to EXE
    si_dir = os.path.realpath('.') + "\\sysinternals\\"
    si_psloglist_exe_path = si_dir + "psloglist.exe -accepteula"

    # [psloglist] setting parameters
    si_psloglist_app_param = " -s -x application"
    si_psloglist_sec_param = " -s -x security"
    si_psloglist_sys_param = " -s -x system"

    # [psloglist] setting execution command
    si_psloglist_app_exec = si_psloglist_exe_path + si_psloglist_app_param
    si_psloglist_sec_exec = si_psloglist_exe_path + si_psloglist_sec_param
    si_psloglist_sys_exec = si_psloglist_exe_path + si_psloglist_sys_param

    # [psloglist] running
    with open('eventlogs-all.csv', 'w') as fout:
        subprocess.call(si_psloglist_app_exec, stdout=fout, stderr=NOERROR)
        subprocess.call(si_psloglist_sec_exec, stdout=fout, stderr=NOERROR)
        subprocess.call(si_psloglist_sys_exec, stdout=fout, stderr=NOERROR)

    # [psloglist] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "eventlogs-all.csv",\
     CASEFOLDER + "/LiveResponseData/EventLogs" + "/" + "eventlogs-all.csv")

def evtparse():
    """Function to collect event logs"""
    print("\n[+] Parsing key events from APP, SEC, SYS, & PowerShell event logs...", flush=True)
    si_dir = os.path.realpath('.') + "\\sysinternals\\"
    si_psloglist_app_evt_list = "104,1022,1033,1034,11707,11708,11724"
    si_psloglist_sec_evt_list1 = "1102,4624,4625,4634,4647,4672,4648,4688,4697,4698"
    si_psloglist_sec_evt_list2 = "4699,4700,4701,4702,4720,4722,4724,4728,4732,4735"
    si_psloglist_sec_evt_list3 = "4738,4756,4776,4778,4779,4798,4799,5140,5145,7034"
    si_psloglist_sec_evt_list4 = "7036,7040"
    si_psloglist_sys_evt_list = "6,104,7035,7045"
    si_psloglist_ps_evt_list = "600,4105,4106"
    pslog_list = [
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
         application".format(si_psloglist_app_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
         security".format(si_psloglist_sec_evt_list1),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
         security".format(si_psloglist_sec_evt_list2),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
        security".format(si_psloglist_sec_evt_list3),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
        security".format(si_psloglist_sec_evt_list4),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
             system".format(si_psloglist_sys_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': 'psloglist.exe -accepteula -s -x -i {} \
         "windows powershell"'.format(si_psloglist_ps_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"}
    ]
    for pslog in pslog_list:
        pslog_running_procs = pslog['Command']
        with open(pslog['output'], "a") as fout:
            subprocess.call(si_dir + pslog_running_procs, stdout=fout, stderr=NOERROR)
    os.rename(os.path.realpath('.') + "/" + pslog_list[0]['output'],
              CASEFOLDER + "/LiveResponseData" + pslog_list[0]['outdir'] + pslog_list[0]['output'])

def prefetch_p():
    """Parse the Prefetch"""
    # [BEGIN] Prefetch Parsing
    print("\n[+] Parsing prefetch data...\n", flush=True)

    # [pf] setting up path to Eric Zimmermans tools
    pecmd_dir = os.path.realpath('.') + "\\PECmd\\"

    # [pf] setting up path to EXE and adding the -d option for directory
    pf_exe_path = pecmd_dir + "PECmd.exe -d  "

    # [pf] directory location of Prefetch files
    pf_directory = "{}\\LiveResponseData\\Prefetch".format(CASEFOLDER)

    # [pf] setting full pf.exe command with args
    pf_command = pf_exe_path + pf_directory

    # Execute the pf command and directing output to a file
    with open('prefetch-out.txt', 'w') as fout:
        subprocess.call(pf_command, stdout=fout)

    # moving prefetch info to case folder
    os.rename(os.path.realpath('.') + "/" + "prefetch-out.txt",
              CASEFOLDER + "\\LiveResponseData\\Prefetch/"
              "prefetch-out.txt")

def registry_stuff():
    """[BEGIN] Registry Extraction"""
    print("[+] Dumping registry hives...\n", flush=True)
    registry_dump_hives = {"NTUSER": 'HKCU', "SAM": r'HKLM\SAM', "SYSTEM": r'HKLM\SYSTEM',
                           "SECURITY": r'HKLM\SECURITY', "SOFTWARE": r'HKLM\SOFTWARE'}
    for hive in registry_dump_hives:
        reg = "cmd.exe /C reg.exe SAVE " + registry_dump_hives[hive]
        reg_out = " " + CASEFOLDER + "\\LiveResponseData\\Registry\\" + hive + " " + hive + ".hiv"
        reg_dump = reg + reg_out
        subprocess.call(reg_dump, stdout=NOERROR, stderr=NOERROR)

    # [END] Registry Extraction

    # [BEGIN] Registry Parsing
    print("[+] Parsing registry hives...\n", flush=True)

    # [Regripper] setting up path to Regripper
    rr_dir = os.path.realpath('.') + "\\regripper\\"

    # [Regripper] setting up path to EXE
    rr_exe_path = rr_dir + "rip.exe"

    # [Regripper] setting parameters
    registry_hives = ["NTUSER", "SAM", "SYSTEM", "SECURITY", "SOFTWARE"]
    for hives in registry_hives:
        param_1 = " -r " + CASEFOLDER + "\\LiveResponseData\\Registry\\" + hives + " -f " + hives
        reg_exec = rr_exe_path + param_1
        out_put_file = "rr." + hives + "-out.txt"
        with open(out_put_file, 'w') as fout:
            subprocess.call(reg_exec, stdout=fout, stderr=NOERROR)
        os.rename(os.path.realpath('.') + "/" + out_put_file, CASEFOLDER +
                  "/LiveResponseData/Registry/regripped-out" + "/" + out_put_file)

def usb_ap():
    """Gather the USB artifacts"""
    # [BEGIN] USB Artifact Parsing
    print("[+] Grabbing more USB artifacts...\n", flush=True)

    # Detecting system architecture
    if os.path.exists("c:\\windows\\system32\\"):
        # variable to point to the location of "xcopy" on the remote system
        xcopy_dir = "c:\\windows\\system32\\"
        # setting up variables to run xcopy with appropriate parameters
        xcopy_param = xcopy_dir + "xcopy.exe C:\\Windows\\inf\\setupapi.dev.log "
        xcopy_out = CASEFOLDER + "\\LiveResponseData\\Registry\\usb-install-log"
        xcopy_usb = xcopy_param + xcopy_out

        # copying USB setup log from target
        subprocess.call(xcopy_usb, stdout=NOERROR, stderr=NOERROR)

    else:
        print("Xcopy missing from target", flush=True)



def data_compress():
    """Allows compression for files """
    print("[+] Compressing triage output... please wait", flush=True)
    # Compress Case Folder output data
    # The Liveresponsedata is compressed to save space but the Forensic
    # images are not so we do not corrupt them
    file_compress_out = TARGETNAME + "." + DATEANDTIME +".zip"
    file_compress_in = "LiveResponseData.zip"
    zip_file_1 = zipfile.ZipFile(file_compress_in, "w", zipfile.ZIP_DEFLATED)
    current_dir = os.getcwd()
    os.chdir(CASEFOLDER)
    for dirname, subdirs, files in os.walk("LiveResponseData"):
        #Make pylint happy :)
        print(subdirs, file=NOERROR)
        zip_file_1.write(dirname)
        for filename in files:
            zip_file_1.write(os.path.join(dirname, filename))

    zip_file_1.close()
    os.chdir(current_dir)
    zip_file_2 = zipfile.ZipFile(file_compress_out, "w")
    os.rename(os.path.realpath('.') + "/" + file_compress_in, CASEFOLDER + "/" + file_compress_in)
    shutil.rmtree(os.path.realpath(CASEFOLDER + "/LiveResponseData"))
    for dirname, subdirs, files in os.walk(CASEFOLDER):
        zip_file_2.write(dirname)
        for filename in files:
            zip_file_2.write(os.path.join(dirname, filename))
    zip_file_2.close()
    shutil.rmtree(os.path.realpath(CASEFOLDER))

def get_browser_history():
    """Collect the browser history"""
    print("[+] Getting User Browsing History...\n", flush=True)
    bhv_dir = os.path.realpath('.') + "\\BrowsingHistoryView\\"
    bhv_exe_path = bhv_dir + BVHRUN
    bhv_param = " /SaveDirect /sort 3 /VisitTimeFilterType 1 /cfg " + \
                "BrowsingHistoryView.cfg /scomma " + CASEFOLDER \
               + "/LiveResponseData/BasicInfo/BrowsingHistoryView.csv  "
    bhv_command = bhv_exe_path + bhv_param
    bhv_run = bhv_command
    subprocess.call(bhv_run, stderr=NOERROR)

def freespace_check(drive):
    """Check for free space on given drive"""
    usage = shutil.disk_usage(drive)
    if (usage.free // (2**30)) < MINDISKSPACE:
        if ARGS.nomem:
            print("\n\t[-] Free space is {} GB\n".format(usage.free // (2**30)), flush=True)
            print("\n[!] Disk space low on target, good thing you weren't wanting memory", flush=True)
        else:
            print("\n\t[-] Free space is {} GB\n".format(usage.free // (2**30)), flush=True)
            print("\n[!] Disk space low on target, memory will need to be skipped", flush=True)
            ARGS.nomem = True

def get_defender_scanlogs():
    """Grab Windows Defender scan log"""
    print("\n[+] Pulling Windows Defender scanlog...", flush=True)
    scanlog_dir = "c:\\programdata\\microsoft\\windows defender\\support\\"
    for root, dirs, files in os.walk(scanlog_dir):
        #Make pylint happy :)
        print(dirs, root, file=NOERROR)
        for file in files:
            if file.startswith("MPLog-"):
                scanlog_src = "{}\\{}".format(scanlog_dir, file)
                scanlog_dst = "{}/LiveResponseData/BasicInfo/Windows_Defender_Scanlogs_{} \
                ".format(CASEFOLDER, file)
                shutil.copy(scanlog_src, scanlog_dst)
            else:
                pass

##########################################################################
#   All function calls should be defined above this.                     #
##########################################################################

banner()
sys.stdout.flush()
has_admin_access()
freespace_check("C:")
env_setup()


if ARGS.memonly:
    mem_scrape()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

# Collect memory as early as possible for all options unless no memory is selected
if not ARGS.nomem:
    mem_scrape()

if ARGS.browserhistonly:
    get_browser_history()
    hash_dir('Triage_File_Collection_Hashlist.csv', CASEFOLDER)
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.hashonly:
    hashing_new("LiveResponseData/BasicInfo/Full_System.txt", "c:\\")
    hash_dir('Triage_File_Collection_Hashlist.csv', CASEFOLDER)
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.evtlogparse:
    evtparse()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.evtlogfiles:
    evtxall()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.evtlogparseall:
    evtparseall()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

pre_fetch()
powershell_history()
last_user()
USERS_LIST = list_users()

#Hash temp dir for all users who have logged onto the system
for user in USERS_LIST:
    hashing_new('LiveResponseData/BasicInfo/Hashes_md5_' + user + \
                '_TEMP_WindowsPE_and_Dates.txt', 'c:\\Users\\'
                + user + '\\AppData\\Local\\Temp')
    sys.stdout.flush()
hashing_new('LiveResponseData/BasicInfo/Hashes_md5_System32_WindowsPE_and_Dates.txt',
            'c:\\windows\\system32')
hashing_new('LiveResponseData/BasicInfo/Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt',
            'c:\\temp')

network_info_gathering()
volatile_data_gather()
system_data_gathering()
windows_update_log()
get_defender_scanlogs()
evtparse()
prefetch_p()
registry_stuff()
usb_ap()
get_browser_history()

# [BEGIN] Hashing all Collected Triage Data
print("[+] Hashing collected triage data...\n", flush=True)
hash_dir('Triage_File_Collection_Hashlist.csv', CASEFOLDER)

data_compress()
banner()
sys.stdout.flush()
env_cleanup()
sys.exit(0)
