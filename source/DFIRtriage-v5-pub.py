# python3

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
##                                                                         ##
#############################################################################

#############################################################################
##                                                                         ##
## DESCRIPTION: Forensic acquisition of volatile data and system           ##
## information for use with initial Incident Response.                     ##
##                                                                         ##
## FILENAME: DFIRtriage.py                                                 ##
## VERSION: 5.0.1                                                          ##
## STATUS: PUB                                                             ##
## LAST MOD: 2/4/21 @ 3:32 PM                                              ##
## AUTHOR: Travis Foley                                                    ##
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
OSARCH = ''
MD5_PATH = ''
CPORTSDIR = ''
WMICDIR = ''
BVHRUN = ''
OSVERSION = sys.getwindowsversion()

if OSVERSION.major == 10:
    LOGGEDUSERS = subprocess.getoutput("whoami")
else:
    LOGGEDUSERS = getpass.getuser()

#setup commandline options
PARSER = argparse.ArgumentParser(
    description='Forensic acquisition of volatile data and system information for use '
    'in initial incident response ', epilog='Example usage: "dfirtriage.exe" (runs all) OR "dfirtriage -bho -nm" (pulls browser history, bypasses memory, exits)')
GROUP = PARSER.add_mutually_exclusive_group(required=False)
GROUP.add_argument('-mo', '--memonly', action='store_true', help="Acquires memory then exits")
GROUP.add_argument('-nm', '--nomem', action='store_true', help="Bypasses memory acquisition")
PARSER.add_argument('-elpa', '--evtlogparseall', action='store_true',
                    help="Parses all Application, System, and Security event log events")
PARSER.add_argument('-elf', '--evtlogfiles', action='store_true', \
 help="Pulls full APP, SEC, & SYS evtx files")
PARSER.add_argument('-ho', '--hashonly', action='store_true', help=r"Hashes all files on C:\ drive then exits")
PARSER.add_argument('-bho', '--browserhistonly', action='store_true', help="Pulls browser history then exits")
PARSER.add_argument('-hl', '--headless', action='store_true', help="Automation support, no user input required")
PARSER.add_argument('-sf', '--systemfiles', action='store_true', help="Collect locked system files")
ARGS = PARSER.parse_args()

VERSION = "5.0.1"
CURRENTUSER = getpass.getuser()

#This is a test to see if we are compiled into a binary or we are just a script

if getattr(sys, 'frozen', False):
    COMPILED = 1
    BUNDLE_DIR = sys._MEIPASS + "/core.ir/"

else:
    COMPILED = 0
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
        print("\n[+] Has Local Admin rights? [NO]\n")
        open("DFIRTriage must be ran as Local ADMIN.txt", 'w')
        sys.exit(0)
    else:
        print("\n[+] Has Local Admin rights? [YES]")

def env_setup():
    """Setup all the enviroment stuff"""
    print("\n[+] Setting up environment\n", flush=True)
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
        print("[+] Detecting OS and System Architecture [64-BIT]", flush=True)
        sys.stdout.flush()
        OSARCH = 64
        MD5_PATH = "{}\\md5deep-4.4\\md5deep64.exe".format(os.path.realpath('.'))
        CPORTSDIR = os.path.realpath('.') + "/cports-x64/"
        WMICDIR = os.path.realpath('.') + "\\WMIC\\"
        BVHRUN = "BrowsingHistoryView.exe"

    else:
        print("[+] Detecting OS and System Architecture [32bit system]")
        sys.stdout.flush()
        OSARCH = 32
        MD5_PATH = "{}\\md5deep-4.4\\md5deep.exe".format(os.path.realpath('.'))
        CPORTSDIR = os.path.realpath('.') + "/cports/"
        WMICDIR = os.path.realpath('.') + "\\WMIC32\\"
        BVHRUN = "BrowsingHistoryView32.exe"

    print("\n[+] Building acquisition directory structure\n", flush=True)
    # This list contains list of all directories that need to be created for output
    app_folders = ["ForensicImages/Memory", "ForensicImages/HDD", "ForensicImages/SystemFiles",
                   "LiveResponseData/BasicInfo", "LiveResponseData/UserInfo",
                   "LiveResponseData/EventLogs",
                   "LiveResponseData/NetworkInfo", "LiveResponseData/PersistenceMechanisms",
                   "LiveResponseData/Registry/regripped-out",
                   "LiveResponseData/Registry/usb-install-log",
                   "LiveResponseData/Prefetch", "LiveResponseData/Prefetch/parsed_prefetch", "LiveResponseData/FileSystem"]
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

    # moving triage info file & dtfind.exe to case folder
    move_to_casefolder = ["Triage_info.txt", "dtfind.exe"]
    for file in move_to_casefolder:
        os.rename(os.path.realpath('.') + "\\{}".format(file), CASEFOLDER + "\\{}".format(file))

def env_cleanup():
    """[END] Compress and Move Output"""
    if ARGS.headless:
        pass
    else:
        print("[*] DFIRtriage process is now complete.\n")
        print("[*] Press any key to clean up.")
        input()

    util_list = ["cports", "cports-x64", "lastactivityview", "md5deep-4.4", "PrcView",
                 "sysinternals", "PECmd", "winutils", "WMIC", "WMIC32", "xcopy", "xcopy64",
                 "memory", "regripper", "BrowsingHistoryView", "FGET"]

    #These are files that need to be cleaned up and not included in the zip
    file_clean_up = ["DFIRtriage must be ran as Local ADMIN.txt", "0", "1", "2", "3", "dtfind.exe"]
    tool_path = os.path.realpath('.')

    for tool in util_list:
        shutil.rmtree(tool_path + "\\" + tool)

    for files in file_clean_up:
        if os.path.exists(files):
            os.remove(files)
            
    print("[x] Clean up complete.")
    if os.path.exists(__file__):
        os.remove(__file__)

def mem_scrape():
    """Scrapes the memory from the target system"""
    print("[+] Memory acquisition\n", flush=True)
    # variable to point to the "memory" subdir of current directory
    mem_dir = os.path.realpath('.') + "\\memory\\"
    # setting up variables to run winpemem with different parameters
    mem_acq_get = mem_dir + "winpmem_mini_x64_rc2.exe memdump.raw"
    # executing winpmem
    subprocess.call(mem_acq_get, stderr=NOERROR)
    # moving acquired memory image to case folder
    os.rename(os.path.realpath('.') + "\\" + "memdump.raw", CASEFOLDER \
        + "\\ForensicImages\\Memory" + "\\" + "memdump.raw")

def pre_fetch():
    """Collects the Prefetch"""
    print("[+] Prefetch collection\n", flush=True)

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
    del list_of_users[-1]
    return list_of_users

def last_user():
    """[BEGIN] Begin LastUser Activity Data Collection"""
    print("[+] Last User Activity collection\n", flush=True)

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

def core_integrity():
    """Check the validity of the core"""
    if os.path.isfile(BUNDLE_DIR + "\\core.ir"):
        print("\n[+] Verifying core integrity", flush=True)

    else:
        os.system('color 4F')
        print("\n[!] This copy is corrupt. Please download a new copy of DFIRtriage.", flush=True)
        sys.exit()

    hasher = hashlib.md5()
    core_val = "52437fddadd0510f5980ef6b4d38c0d0"
    with open(BUNDLE_DIR + '\\core.ir', 'rb') as corefile:
        buf = corefile.read()
        hasher.update(buf)

    core_check = hasher.hexdigest()
    if core_val == core_check:
        print("\n[+] Core integrity [OK]", flush=True)

    else:
        os.system('color 4F')
        print("\n[!] Hash values do not match. Integrity check failed. Please download a new copy of DFIRtriage.", flush=True)
        sys.exit()

# def legacy_banner():
#     """This is our OG banner"""
#     print("\n")
#     print(r"####################################################")
#     print(r"#          ________ _     __   ___ _  ___          #")
#     print(r"#         / _/_   _| |   | _\ | __| || _ \         #")
#     print(r"#        | \__ | | | |   | v || _|| || v /         #")
#     print(r"#         \__/ |_| |_|   |__/\/_|\/_\/_|_\         #")
#     print(r"#   _____ ___ _  __   __ ___   _____ __   __  _    #")
#     print(r"#  |_   _| _ \ |/  \ / _] __| |_   _/__\ /__\| |   #")
#     print(r"#    | | | v / | /\ | [/\ _|    | || \/ | \/ | |_  #")
#     print(r"#    |_| |_|_\_|_||_|\__/___|   |_| \__/ \__/|___| #")
#     print(r"#                                                  #")
#     print(r"#                   Version {}                  #".format(VERSION))
#     print(r"#                                                  #")
#     print(r"####################################################")
#     print("\n")

def banner():
    """This is our new banner"""
    print('''
    
                - - - - - - - - - - - - - - - - - - - 
  ______   _______ ___  _______  __         __                   
 |   _  \ |   _   |   ||   _   \|  |_.----.|__|.---.-.-----.-----.
 |.  |   \|.  1___|.  ||.  l   /|   _|   _||  ||  _  |  _  |  -__|
 |.  |    \.  __) |.  ||.  _   1|____|__|  |__||___._|___  |_____|
 |:  1    /:  |   |:  ||:  |   |                     |_____|      
 |::.. . /|::.|   |::.||::.|:. |                                       
 `------' `---'   `---'`--- ---'                                
                - - - - - - - - - - - - - - - - - - - 
                          PUBLIC RELEASE
                              v{}
                - - - - - - - - - - - - - - - - - - -
    
    
    '''.format(VERSION))


def volatile_data_gather():
    """Gathers the volatile data"""
    print("\n[+] Gather additional volatile data\n", flush=True)

    # grabbing host file
    hosts_file = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    hosts_file_dst = "{}/LiveResponseData/NetworkInfo/{}".format(CASEFOLDER, "hosts.txt")
    os.system("type {} > {}".format(hosts_file, hosts_file_dst))

    procs = [
        {'Command': "cmd.exe /C tasklist /V", 'output': "Running_processes.txt",
         'outdir': "/BasicInfo/"},
        {'Command': "{}/pv.exe -m -e *".format(os.path.realpath('./prcview')), 'output': "Loaded_dlls.txt",
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
        {'Command': r"cmd.exe /C tree C:\ /F /A", 'output': "Full_file_listing.txt",
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
    print("[+] Network information gathering", flush=True)
    print("\n\t" + "[-] Collecting currently open TCP/UDP ports", flush=True)
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
    '''Convert ETL files to Windows Update log'''
    winuplog_src = "c:\\temp\\WindowsUpdate.log"
    winuplog_dst = CASEFOLDER + "\\LiveResponseData\\BasicInfo\\WindowsUpdate.log"
    winuplog_run = "cmd /c powershell Get-WindowsUpdateLog -LogPath c:\\temp\\WindowsUpdate.log > nul"
    print("\n[+] Building Windows Update log from event trace log files", flush=True)

    if not os.path.isdir("C:\\Program Files (x86)\\Windows Defender\\"):
        try:
            os.makedirs("C:\\Program Files (x86)\\Windows Defender\\")
        except PermissionError:
            pass
    if not os.path.isfile("C:\\Program Files (x86)\\Windows Defender\\SymSrv.dll"):
        try:
            with open("C:\\Program Files (x86)\\Windows Defender\\SymSrv.dll", "w") as plug:
                plug.write("Pluggin a hole")
            plug.close()
        except PermissionError:
            pass

    subprocess.call(winuplog_run)

    try:
        if os.path.isfile(winuplog_src):
            shutil.move(winuplog_src, winuplog_dst)
        else:
            print("\n[!] Windows Update log was not generated correctly.")
    except IOError as io_error:
        print(io_error)
        sys.exit("\n[!] Ouch! Something went wrong, but I'm not sure what :).")

def powershell_history():
    """Grab powershell console command history file"""
    print("[+] Acquiring existing powershell command history for all users\n", flush=True)
    user_list = os.popen("cmd.exe /C dir c:\\Users /b ")
    for users in user_list:
        users = users.strip()
        ps_history_src = "c:\\users\\{}\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt".format(users)
        ps_history_dst = CASEFOLDER + "\\LiveResponseData\\BasicInfo\\powershell_command_history_{}.txt".format(users)

        try:
            if os.path.isfile(ps_history_src):
                print("\t[+] Checking '{}' [OK]".format(users))
                shutil.copy(ps_history_src, ps_history_dst)
            else:
                print("\t[-] Checking '{}' [NOT FOUND]".format(users))
        except IOError as io_error_2:
            print(io_error_2)
            sys.exit("\n[!] Ouch! Something went wrong, but I'm not sure what :).")
    print()

def system_data_gathering():
    """Gather system data"""
    # [BEGIN] System Data Gathering
    print("[+] Gather system data\n", flush=True)
    print("[+] Run Sysinternals tools\n", flush=True)
    print("\t[-] Accepting EULA", flush=True)
    print("\t[-] Executing toolset", flush=True)
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

def evtparseall():
    """Function to parse all events in the APP, SEC, & SYS event logs"""
    print("[+] Parsing all events in the APP, SEC, & SYS event logs\n", flush=True)
    # [psloglist] setting up path to EXE
    si_dir = os.path.realpath('.') + "\\sysinternals\\"
    si_psloglist_exe_path = si_dir + "psloglist.exe -accepteula"

    # [psloglist] setting parameters
    si_psloglist_app_param = " -s -x application"
    si_psloglist_sec_param = " -s -x security"
    si_psloglist_sys_param = " -s -x system"
    si_psloglist_ps_param = ' -s -x "Windows PowerShell"'

    # [psloglist] setting execution command
    si_psloglist_app_exec = si_psloglist_exe_path + si_psloglist_app_param
    si_psloglist_sec_exec = si_psloglist_exe_path + si_psloglist_sec_param
    si_psloglist_sys_exec = si_psloglist_exe_path + si_psloglist_sys_param
    si_psloglist_ps_exec = si_psloglist_exe_path + si_psloglist_ps_param

    # [psloglist] running
    with open('eventlogs-all.csv', 'w') as fout:
        subprocess.call(si_psloglist_app_exec, stdout=fout, stderr=NOERROR)
        subprocess.call(si_psloglist_sec_exec, stdout=fout, stderr=NOERROR)
        subprocess.call(si_psloglist_sys_exec, stdout=fout, stderr=NOERROR)
        subprocess.call(si_psloglist_ps_exec, stdout=fout, stderr=NOERROR)

    # [psloglist] moving output to case folder
    os.rename(os.path.realpath('.') + "/" + "eventlogs-all.csv",\
     CASEFOLDER + "/LiveResponseData/EventLogs" + "/" + "eventlogs-all.csv")

def evtparse():
    """Function to collect event logs"""
    print("\n[+] Parsing key events from APP, SEC, SYS, & PowerShell event logs\n", flush=True)
    si_dir = os.path.realpath('.') + "\\sysinternals\\"
    si_psloglist_app_evt_list = "1022,1033,1034,11707,11708,11724"
    si_psloglist_sec_evt_list = "1102,4624,4625,4634,4647,4672,4648,\
4688,4697,4698,4699,4700,4701,4702,4720,4722,4724,4728,4732,\
4735,4738,4756,4776,4778,4779,4798,4799,5140,5145,7034,7036,7040"
    si_psloglist_sys_evt_list = "6,104,7035,7045"
    si_psloglist_ps_evt_list = "600,4105,4106"
    pslog_list = [
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
         Application".format(si_psloglist_app_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
         Security".format(si_psloglist_sec_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': "psloglist.exe -accepteula -s -x -i {} \
         System".format(si_psloglist_sys_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"},
        {'Command': 'psloglist.exe -accepteula -s -x -i {} \
         "Windows PowerShell"'.format(si_psloglist_ps_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/EventLogs/"}
        ]
    for pslog in pslog_list:
        pslog_running_procs = pslog['Command']
        with open(pslog['output'], "a") as fout:
            subprocess.call(si_dir + pslog_running_procs, stdout=fout, stderr=subprocess.STDOUT, shell=True)
    os.rename(os.path.realpath('.') + "/" + pslog_list[0]['output'],
              CASEFOLDER + "/LiveResponseData" + pslog_list[0]['outdir'] + pslog_list[0]['output'])

def evtxall():
    """Function to pull full APP, SYS, and SEC event log (evtx) files"""
    print("[+] Grabbing App, Sys, and Sec (.evtx) files\n", flush=True)

    # Setting System32 dir reference based on the target system architecture
    # ref. https://www.samlogic.net/articles/sysnative-folder-64-bit-windows.htm

    if COMPILED == 0:
        event_log_path = r"C:\Windows\System32\winevt\Logs"
    else:
        if OSARCH == 64:
            event_log_path = r"C:\Windows\Sysnative\winevt\Logs"
        else:
            event_log_path = r"C:\Windows\System32\winevt\Logs"

    app_log_src = r"{}\Application.evtx".format(event_log_path)
    app_log_dst = CASEFOLDER + r"\LiveResponseData\EventLogs"
    sys_log_src = r"{}\System.evtx".format(event_log_path)
    sys_log_dst = CASEFOLDER + r"\LiveResponseData\EventLogs"
    sec_log_src = r"{}\Security.evtx".format(event_log_path)
    sec_log_dst = CASEFOLDER + r"\LiveResponseData\EventLogs"

    # executing file copy using shutil.copy2 in order to preserve file metadata
    shutil.copy2(app_log_src, app_log_dst)
    shutil.copy2(sys_log_src, sys_log_dst)
    shutil.copy2(sec_log_src, sec_log_dst)


def prefetch_p():
    """Parse the Prefetch"""
    # [BEGIN] Prefetch Parsing
    print("\n[+] Parsing prefetch data\n", flush=True)

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
              CASEFOLDER + "\\LiveResponseData\\Prefetch\\parsed_prefetch/"
              "prefetch-out.txt")

def registry_stuff():
    """[BEGIN] Registry Extraction"""
    print("[+] Dumping registry hives\n", flush=True)
    registry_dump_hives = {"SAM": r'HKLM\SAM', "SYSTEM": r'HKLM\SYSTEM',
                           "SECURITY": r'HKLM\SECURITY', "SOFTWARE": r'HKLM\SOFTWARE'}
    for hive in registry_dump_hives:
        reg = "cmd.exe /C reg.exe SAVE " + registry_dump_hives[hive]
        reg_out = " " + CASEFOLDER + "\\LiveResponseData\\Registry\\" + hive + " " + hive + ".hiv"
        reg_dump = reg + reg_out
        subprocess.call(reg_dump, stdout=NOERROR, stderr=NOERROR)

    # [END] Registry Extraction

    # [BEGIN] Registry Parsing
    print("[+] Parsing registry hives\n", flush=True)

    # [Regripper] setting up path to Regripper
    rr_dir = os.path.realpath('.') + "\\regripper\\"

    # [Regripper] setting up path to EXE
    rr_exe_path = rr_dir + "rip.exe"

    # [Regripper] setting parameters
    registry_hives_os = ["SAM", "SYSTEM", "SECURITY", "SOFTWARE"]
    for hives in registry_hives_os:
        param_1 = " -r " + CASEFOLDER + "\\LiveResponseData\\Registry\\" + hives + " -f " + hives
        reg_exec = rr_exe_path + param_1
        out_put_file = "rr." + hives + "-out.txt"
        with open(out_put_file, 'w') as fout:
            subprocess.call(reg_exec, stdout=fout, stderr=NOERROR)
        os.rename(os.path.realpath('.') + "/" + out_put_file, CASEFOLDER +
                  "/LiveResponseData/Registry/regripped-out" + "/" + out_put_file)

    # [Regripper] building user reg file list
    for root, dirs, files in os.walk(CASEFOLDER + "\\LiveResponseData\\Registry\\"):
        registry_hives_users = [file for file in files if file.endswith(".DAT")]
        # [Regripper] processing user reg files with regripper
        for userreg in registry_hives_users:
            if "USRCLASS" in userreg:
                param_2 = " -r " + CASEFOLDER + "\\LiveResponseData\\Registry\\" + userreg + " -f USRCLASS"
                reg_exec2 = rr_exe_path + param_2
                out_put_file2 = "rr." + userreg + "-out.txt"
                with open(out_put_file2, 'w') as fout2:
                    subprocess.call(reg_exec2, stdout=fout2, stderr=NOERROR)
                fout2.close()
                os.rename(os.path.realpath('.') + "/" + out_put_file2, CASEFOLDER + "/LiveResponseData/Registry/regripped-out" + "/" + out_put_file2)
            if "NTUSER" in userreg:
                param_3 = " -r " + CASEFOLDER + "\\LiveResponseData\\Registry\\" + userreg + " -f NTUSER"
                reg_exec3 = rr_exe_path + param_3
                out_put_file3 = "rr." + userreg + "-out.txt"
                with open(out_put_file3, 'w') as fout3:
                    subprocess.call(reg_exec3, stdout=fout3, stderr=NOERROR)
                fout3.close()
                os.rename(os.path.realpath('.') + "/" + out_put_file3, CASEFOLDER + "/LiveResponseData/Registry/regripped-out" + "/" + out_put_file3)

def usb_ap():
    """Gather the USB artifacts"""
    # [BEGIN] USB Artifact Parsing
    print("[+] Grab more USB artifacts\n", flush=True)

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
    print("[+] Compressing triage output, please wait", flush=True)
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
    print("[+] Getting User Browsing History\n", flush=True)
    bhv_dir = os.path.realpath('.') + "\\BrowsingHistoryView\\"
    bhv_exe_path = bhv_dir + BVHRUN
    bhv_param = " /SaveDirect /sort 3 /VisitTimeFilterType 1 /cfg " + "BrowsingHistoryView.cfg /scomma " + CASEFOLDER + "/LiveResponseData/BasicInfo/BrowsingHistoryView.csv  "
    bhv_command = bhv_exe_path + bhv_param
    bhv_run = bhv_command
    subprocess.call(bhv_run, stderr=NOERROR)

def freespace_check(drive, minspace):
    """Check for free space on given drive"""
    usage = shutil.disk_usage(drive)
    if (usage.free // (2**30)) < minspace:
        if ARGS.nomem:
            print("\n[+] Checking free space", flush=True)
            print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
            print("\n\t[!] Disk space low on target, good thing you weren't wanting memory", flush=True)
        if ARGS.memonly:
            print("\n[+] Checking free space", flush=True)
            print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
            print("\n\t[!] Disk space low on target, unable to dump memory. Please free up space on target and retry.", flush=True)
            sys.exit()
        if ARGS.systemfiles:
            print("\n[+] Checking for additional free space for locked system files", flush=True)
            print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
            print("\n\t[!] Disk space too low on target, unable to grab system files\n. \n\t[!] Free up space or remove -sf argument and retry.\n", flush=True)
            env_cleanup()
            sys.exit()
        else:
            print("\n[+] Checking free space", flush=True)
            print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
            print("\n\t[!] Disk space low on target, memory will need to be skipped\n", flush=True)
            ARGS.nomem = True


def get_defender_scanlogs():
    """Grab Windows Defender scan log"""
    print("\n[+] Pulling Windows Defender scanlog", flush=True)
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

def fget_copy(val):
    """Use fget to copy User registry files that are in use"""

    if " Documents" in val:
        pass
    elif val == "Public":
        pass
    elif val == "ADMINI~1":
        pass
    else:
        print("[+] Grab locked files from " + val + "\n")
        files = ""
        file_list = "cmd.exe /C dir /a c:\\Users\\" + "\"" + val + "\"" + "\\" +"NTUSER.dat*" + " /b "
        all_ntuser_dat = subprocess.check_output(file_list, stderr=NOERROR, universal_newlines=True)
        list_of_files = all_ntuser_dat.rsplit("\n")
        fget_dir = os.path.realpath('.') + "\\FGET\\"
        for files in list_of_files:
            if files == "":
                pass
            else:
                fget_usrclass_output = CASEFOLDER + "/LiveResponseData/Registry/" + val + "_" + "USRCLASS.DAT"
                fget_ntuser_output = CASEFOLDER + "/LiveResponseData/Registry/" + "\"" + val + "\"" + "_" + files
                fget_exe_path = fget_dir + "FGET.exe -extract" + r' c:\Users\\' + "\"" + val + "\""+ "\\" + files + " " + fget_ntuser_output
                fget_exe_usrclass_path = fget_dir + "FGET.exe -extract" + " c:\\Users\\" + val + "\\AppData\\Local\\Microsoft\\Windows\\USRCLASS.DAT" + " " + fget_usrclass_output
                # Foresic copy of users NTUSER.DAT & USRCLASS.DAT
                subprocess.call(fget_exe_path, stdout=NOERROR, stderr=NOERROR)
                subprocess.call(fget_exe_usrclass_path, stdout=NOERROR, stderr=NOERROR)

def collect_locked_system_files():
    """Using Fget to copy locked system files"""
    print("[+] Collecting locked system files \n")

    if COMPILED == 0:
        system_files = {"hiberfil.sys" : r'c:', "pagefile.sys" : r'c:', "srudb.dat" : r'c:\windows\system32\sru'}
    else:
        if OSARCH == 64:
            system_files = {"hiberfil.sys" : r'c:', "pagefile.sys" : r'c:', "srudb.dat" : r'c:\windows\Sysnative\sru'}
        else:
            system_files = {"hiberfil.sys" : r'c:', "pagefile.sys" : r'c:', "srudb.dat" : r'c:\windows\system32\sru'}

    fget_dir = os.path.realpath('.') + "\\FGET\\"

    for sysfiles in system_files:
        col_sys_file_output = CASEFOLDER + "/ForensicImages/SystemFiles/" + sysfiles
        col_sys_file_exe_path = fget_dir + "FGET.exe -extract" + " " + system_files[sysfiles] + "\\" + sysfiles + " " + col_sys_file_output
        subprocess.call(col_sys_file_exe_path, stdout=NOERROR, stderr=NOERROR)


##########################################################################
#   All function calls should be defined above this.                     #
##########################################################################

banner()
sys.stdout.flush()
has_admin_access()
core_integrity()
env_setup()


if ARGS.memonly:
    freespace_check("C:", 60)
    mem_scrape()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

# Collect memory as early as possible for all options unless no memory or system files is selected
if not ARGS.nomem:
    if ARGS.systemfiles:
        print("[i] Acquiring both memory and system files in a single run is not recommended [BYPASSING MEMDUMP]\n")
    else:
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
    hashing_new("LiveResponseData/BasicInfo/Full_System_Hash.txt", "c:\\")
    hash_dir('Triage_File_Collection_Hashlist.csv', CASEFOLDER)
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.evtlogparseall:
    evtparseall()

if ARGS.evtlogfiles:
    evtxall()

if ARGS.systemfiles:
    freespace_check("C:", 100)
    collect_locked_system_files()

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

hashing_new('LiveResponseData/BasicInfo/Hashes_md5_System32_WindowsPE_and_Dates.txt', 'c:\\windows\\system32')
hashing_new('LiveResponseData/BasicInfo/Hashes_md5_System_TEMP_WindowsPE_and_Dates.txt', 'c:\\temp')


for user in USERS_LIST:
    fget_copy(user)

network_data_gathering()
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
print("[+] Hashing collected triage data\n", flush=True)
hash_dir('Triage_File_Collection_Hashlist.csv', CASEFOLDER)

data_compress()
banner()
sys.stdout.flush()
env_cleanup()
sys.exit(0)
