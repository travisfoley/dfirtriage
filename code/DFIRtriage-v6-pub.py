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
## VERSION: 6.0                                                            ##
## STATUS: DEV                                                             ##
## LAST MOD: 12/13/23 @ 8:30 AM                                            ##
## AUTHOR: Travis Foley                                                    ##
#############################################################################

'''
NOTES:
version 6.0 complete
'''

# Built-in Imports:
import os
import psutil
import csv
from datetime import datetime
import time
import socket
import sys
import ctypes
import subprocess
import shutil
import zipfile
import argparse
import getpass
import hashlib
from tqdm import tqdm
global public_ip
import public_ip as pub_ip

NOERROR = open(os.devnull, 'w')
TARGETNAME = socket.gethostname()
DATEANDTIME = time.strftime("%Y%m%d%H%M%S")
DATE_TIME_NORM = time.strftime("%m-%d-%Y %H:%M:%S")
START_TIME = time.strftime("%H:%M:%S")
stime = datetime.strptime(START_TIME, "%H:%M:%S")
CASEFOLDER = TARGETNAME + "." + DATEANDTIME
END_TIME = time.strftime("%H:%M:%S")
OSARCH = ''
MD5_PATH = ''
CPORTSDIR = ''
WMICDIR = ''
BVHRUN = ''
OSVERSION = sys.getwindowsversion()
VERSION = "6.0"
CURRENTUSER = getpass.getuser()

if OSVERSION.major == 10:
    LOGGEDUSERS = subprocess.getoutput("whoami")
else:
    LOGGEDUSERS = getpass.getuser()

#setup commandline options
PARSER = argparse.ArgumentParser(
    description='Forensic acquisition of volatile data and system information for use '
    'in initial incident response ', epilog='Example usage: "dfirtriage -bl -xip" will run default collection in addition to grabbing Bitlocker keys and external IP address')
GROUP = PARSER.add_mutually_exclusive_group(required=False)
GROUP.add_argument('-m', '--memory', action='store_true', help="Acquires memory and continues with artifact collection")
GROUP.add_argument('-p', '--pagefile', action='store_true', help="Acquires paged memory file (pagefile.sys)")
GROUP.add_argument('-hf', '--hiberfil', action='store_true', help="Acquires hibernation memory file (hiberfil.sys)")
PARSER.add_argument('-mo', '--memonly', action='store_true', help="Acquires memory then exits")
PARSER.add_argument('-po', '--pageonly', action='store_true', help="Acquires paged memory file (pagefile.sys) then exits")
PARSER.add_argument('-hfo', '--hiberfonly', action='store_true', help="Acquires hibernation memory file (hiberfil.sys) then exits")
PARSER.add_argument('-bho', '--browserhistonly', action='store_true', help="Pulls browser history then exits")
PARSER.add_argument('-bl', '--bitlocker', action='store_true', help="Dumps bitlocker keys")
PARSER.add_argument('-elpa', '--evtlogparseall', action='store_true', help="Parses all Application, System, Security, and Powershell event logs")
PARSER.add_argument('-elf', '--evtlogfiles', action='store_true', help="Pulls full APP, SEC, SYS, Powershell, & Firewall evtx files")
PARSER.add_argument('-xip', '--externalip', action='store_true', help="Grabs the external IP address of the host.")
PARSER.add_argument('-sdb', '--srumdb', action='store_true', help="Collect system resource ulization monitor (SRUM) database (srudb.dat)")
PARSER.add_argument('-md5', '--md5hash', action='store_true', help=r"MD5 hash all execuatable files on OS drive. DISABLE A/V REALTIME SCANNING FOR FASTER PERFORMANCE.")
PARSER.add_argument('-sha1', '--sha1hash', action='store_true', help=r"SHA-1 hash all execuatable files on OS drive. DISABLE A/V REALTIME SCANNING FOR FASTER PERFORMANCE.")
PARSER.add_argument('-sha256', '--sha256hash', action='store_true', help=r"SHA-256 hash all execuatable files on OS drive. DISABLE A/V REALTIME SCANNING FOR FASTER PERFORMANCE.")
ARGS = PARSER.parse_args()


def banner():
    print("                                                     ")
    print("  (     (    (   (                                   ")
    print("  )\ )  )\ ) )\ ))\ )    *   )                       ")
    print(" (()/( (()/((()/(()/(  ` )  /((  (     ) (  (    (   ")
    print("  /(_)) /(_))/(_))(_))  ( )(_))( )\ ( /( )\))(  ))\  ")
    print(" (_))_ (_))_(_))(_))   (_(_()|()((_))(_)|(_))\ /((_) ")
    print("  |   \| |_ |_ _| _ \  |_   _|((_|_|(_)_ (()(_|_))   ")
    print("  | |) | __| | ||   /    | | | '_| / _` / _` |/ -_)  ")
    print("  |___/|_|  |___|_|_\    |_| |_| |_\__,_\__, |\___|  ")
    print("                                        |___/        ")
    print("        - - - - - - - - - - - - - - - - - - -        ")
    print("           P U B L I C    R E L E A S E              ")
    print("        - - - - - - - - - - - - - - - - - - -        ")
    print("                                                     ")
    print("                     version {}      ".format(VERSION))
    print("                                                     ")
    print("                                                     ")


if ARGS.md5hash and (ARGS.sha1hash or ARGS.sha256hash):
    banner()
    print("[!] Oops, hash arguments are mutually exclusive, retry selecting only one method.\n")
    sys.exit(2)


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
        print("[+] Has Local Admin rights? [NO]\n")
        open("DFIRTriage must be ran as Local ADMIN.txt", 'w')
        sys.exit(0)
    else:
        print("[+] Has Local Admin rights? [YES]")


def env_setup():
    """Setup all the environment stuff"""
    print("\n[+] Setting up environment", flush=True)

    # Preventing target from sleeping
    pwrcfg = "c:\\windows\\system32\\powercfg.exe -change "
    pwrcfg_args = ["-monitor-timeout-ac 0", "-monitor-timeout-dc 0", "-disk-timeout-ac 0",
    "-disk-timeout-dc 0", "-standby-timeout-ac 0", "-standby-timeout-dc 0", "-hibernate-timeout-ac 0",
    "-hibernate-timeout-dc 0"]
    print("\n[+] Caffeinating endpoint")
    for i in pwrcfg_args:
        os.system(pwrcfg+i)
    print("\n[+] Sleep prevention complete\n")

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
        CPORTSDIR = os.path.realpath('.') + "/cports-x64/"
        WMICDIR = os.path.realpath('.') + "\\WMIC\\"
        BVHRUN = "BrowsingHistoryView.exe"

    else:
        print("[+] Detecting OS and System Architecture [32bit system]")
        sys.stdout.flush()
        OSARCH = 32
        CPORTSDIR = os.path.realpath('.') + "/cports/"
        WMICDIR = os.path.realpath('.') + "\\WMIC32\\"
        BVHRUN = "BrowsingHistoryView32.exe"

    print("\n[+] Building acquisition directory structure\n", flush=True)

    # This list contains list of all directories that need to be created for output
    app_folders = ["ForensicImages/memory", "ForensicImages/hdd", "ForensicImages/system-files", "LiveResponseData/user",
                   "LiveResponseData/logs", "LiveResponseData/system", "LiveResponseData/processes",
                   "LiveResponseData/network", "LiveResponseData/network/WLAN Report", "LiveResponseData/persistence",
                   "LiveResponseData/registry", "LiveResponseData/registry/raw",
                   "LiveResponseData/usbdevices", "LiveResponseData/usbdevices/usb-install-logs", "LiveResponseData/prefetch",
                   "LiveResponseData/prefetch/raw", "LiveResponseData/filesystem", "LiveResponseData/hashes"]
    if not os.path.exists(CASEFOLDER):
        os.makedirs(CASEFOLDER)
    for folder in app_folders:
        os.makedirs(CASEFOLDER + "/" + folder)
    pversion = sys.version_info
    pversion_final = ''
    for ver_sec in pversion:
        pversion_final += str(ver_sec) + '.'

    # Capture version and commandline options
    with open('runlog.txt', 'w') as fout:
        fout.write('Hostname: ' + TARGETNAME + '\n')
        fout.write('User : ' + CURRENTUSER + '\n')
        fout.write('Start time: ' + DATE_TIME_NORM + '\n')
        fout.write('Version: ' + VERSION + '\n')
        fout.write('Commandline options: ' +str(sys.argv)  + '\n')
        fout.write('Python version: ' + pversion_final + '\n')
        fout.write('Logged in users: ' + LOGGEDUSERS + '\n')

    fout.close()

    # moving triage info file & dtfind.exe to case folder
    move_to_casefolder = ["runlog.txt", "dtfind.exe"]
    for file in move_to_casefolder:
        os.rename(os.path.realpath('.') + "\\{}".format(file), CASEFOLDER + "\\{}".format(file))


def env_cleanup():
    """[END] Compress and Move Output"""
    util_list = ["cports", "cports-x64", "lastactivityview", "PrcView",
                 "sysinternals", "PECmd", "EvtxECmd", "WMIC", "WMIC32", "xcopy", "xcopy64",
                 "memory", "regripper", "BrowsingHistoryView", "userprofilesview", "FGET"]

    #These are files that need to be cleaned up and not included in the zip
    file_clean_up = ["DFIRtriage must be ran as Local ADMIN.txt", "0", "1", "2", "3", "dtfind.exe", "Microsoft-Windows-VHDMP-Operational.evtx", "Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx", "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx", "full_file_list.csv.txt"]
    tool_path = os.path.realpath('.')

    for tool in util_list:
        shutil.rmtree(tool_path + "\\" + tool)

    for files in file_clean_up:
        if os.path.exists(files):
            os.remove(files)
    else:
        print("[+] Cleaning up\n\n[+] Triage acquisition complete.")
        if os.path.exists(__file__):
            os.remove(__file__)


def mem_scrape():
    """Acquires a raw memory dump from the target system"""
    print("[+] Dumping memory\n", flush=True)
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
    print("[+] Collecting prefetch\n", flush=True)

    # Detecting system architecture
    if os.path.exists("c:\\windows\\system32\\"):
        # variable to point to the location of "xcopy" on the remote system
        xcopy_dir = "c:\\windows\\system32\\"
        # setting up variables to run xcopy with appropriate parameters
        xcopy_param = xcopy_dir + "xcopy.exe /s/e/h/i C:\\Windows\\Prefetch\\*.pf "
        xcopy_out = CASEFOLDER + "\\LiveResponseData\\Prefetch\\raw"
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
    verfied_user_list = []
    for user in list_of_users:
        if os.path.exists("c:\\users\\{}\\ntuser.dat".format(user)):
            verfied_user_list.append(user)
        else:
            pass
    return verfied_user_list



def last_user():
    """[BEGIN] Begin LastUser Activity Data Collection"""
    print("\n[+] Generating last user activity report\n", flush=True)

    # variable to point to the "lastactivityview" subdir of current directory
    lav_dir = os.path.realpath('.') + "/lastactivityview/"

    # setting up variables to run LastActivityView with output parameters
    lav_run = lav_dir + "LastActivityView.exe /shtml "
    lav_param = CASEFOLDER + "/LiveResponseData/user" + "/LastActivityView.html"
    lav_exe = lav_run + lav_param

    # executing lastactivityview
    subprocess.call(lav_exe)


def hash_exes():
    exe_file_list = []
    no_access = 0
    exe_count = len(exe_file_list)
    print("[+] Gathering all EXE and DLL files\n", flush=True)

    # Walking through files and dirs from root
    for root, dirs, files in os.walk('C:\\'):
        for file in files:
            filestr = str(file)
            # Check if the file is executable
            if filestr.endswith(".exe"):
                file_path = os.path.join(root, file)
                exe_file_list.append(file_path)
            elif filestr.endswith(".dll"):
                file_path = os.path.join(root, file)
                exe_file_list.append(file_path)
            else:
                continue

    file_info_list = []

    print("[+] Hashing EXE and DLL files\n", flush=True)
    print("    NOTE: Disabling real-time AV protection during file hashing will speed up the process\n", flush=True)
    total=len(exe_file_list)
    for exe in exe_file_list:

        try:
            # Grabbing file info
            file_stat = os.stat(exe)
            creation_time = datetime.fromtimestamp(file_stat.st_ctime)
            modified_time = datetime.fromtimestamp(file_stat.st_mtime)

            #Calculate hash values
            if ARGS.md5hash:
                with open(exe, 'rb') as f:
                    file_hash_md5 = hashlib.md5(f.read()).hexdigest()
                f.close()

            if ARGS.sha1hash:
                with open(exe, 'rb') as f:
                    file_hash_sha1 = hashlib.sha1(f.read()).hexdigest()
                f.close()

            if ARGS.sha256hash:
                with open(exe, 'rb') as f:
                    file_hash_sha256 = hashlib.sha256(f.read()).hexdigest()
                f.close()

            # Append file information to the list
            if ARGS.md5hash:
                file_info_list.append([exe, creation_time, modified_time, file_hash_md5])

            if ARGS.sha1hash:
                file_info_list.append([exe, creation_time, modified_time, file_hash_sha1])

            if ARGS.sha256hash:
                file_info_list.append([exe, creation_time, modified_time, file_hash_sha256])

        except(PermissionError, OSError):
            no_access += 1
            pass

    print("\n[i] File hashing complete with access denied for {} files\n".format(no_access), flush=True)


    # Write file information to a csv file

    try:
        with open("hash-report.csv", 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            if ARGS.md5hash:
                csv_writer.writerow(['File', 'Creation Date', 'Modified Date', 'MD5'])
            if ARGS.sha1hash:
                csv_writer.writerow(['File', 'Creation Date', 'Modified Date', 'SHA-1'])
            if ARGS.sha256hash:
                csv_writer.writerow(['File', 'Creation Date', 'Modified Date', 'SHA-256'])
            csv_writer.writerows(file_info_list)

        csv_file.close()

    except PermissionError:
        print("\n[!] Ouch, it appears hash-report.csv is still open. Please close and rerun if you want the new hash report.")

    os.rename(os.path.realpath('.') + "/" + "hash-report.csv", CASEFOLDER +
              "/LiveResponseData/hashes" + "/" + "hash-report.csv")


def triage_acquistion_hash():
    dfirt_file_list = []
    dfirt_file_count = len(dfirt_file_list)

    # Iterate through all files in the current directory and its subdirectories
    triage_data_loc = CASEFOLDER
    for root, dirs, files in os.walk(triage_data_loc):
        for file in files:
            filestr = str(file)
            file_path = os.path.join(root, file)
            dfirt_file_list.append(file_path)

    file_info_list = []

    with tqdm(total=len(dfirt_file_list), desc="[+] Hashing triage artifacts", unit="file") as pbar:
        for artifact in dfirt_file_list:
            pbar.update(1)

            #Calculate hash values
            with open(artifact, 'rb') as f:
                file_hash_sha256 = hashlib.sha256(f.read()).hexdigest()
            f.close()

            # Append file information to the list
            file_info_list.append([artifact, file_hash_sha256])

    # Write file information to a csv file

    try:
        with open("triage_acquisition_hashlist.csv", 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(['Artifact', 'SHA-256'])
            csv_writer.writerows(file_info_list)

        csv_file.close()

    except PermissionError:
        print("\n[!] Ouch, it appears hash-report.csv is still open. Please close and rerun if you want the new hash report.")

    # moving hash file to case folder
    move_to_casefolder = ["triage_acquisition_hashlist.csv"]
    for file in move_to_casefolder:
        os.rename(os.path.realpath('.') + "\\{}".format(file), CASEFOLDER + "\\{}".format(file))


def core_integrity():
    """Check the validity of the core"""
    if os.path.isfile(BUNDLE_DIR + "\\core.ir"):
        print("\n[+] Verifying core integrity", flush=True)

    else:
        os.system('color 4F')
        print("\n[!] Oops, this copy of the DFIRTriage script is corrupt. "
              "Please download a new copy of DFIRtriage.", flush=True)
        sys.exit()

    hasher = hashlib.md5()
    core_val = "49e8595f34f699f708c8ccaa64e95959"
    with open(BUNDLE_DIR + '\\core.ir', 'rb') as corefile:
        buf = corefile.read()
        hasher.update(buf)

    core_check = hasher.hexdigest()
    if core_val == core_check:
        print("\n[+] Core integrity [OK]", flush=True)

    else:
        os.system('color 4F')
        print("\n[!] Oops, hash values do not match. Integrity check failed. Please email"
              " forensics@ehi.com and request latest version.", flush=True)
        sys.exit()


def generate_file_list(root_path, output_file):
    print("\n[+] Building C drive file list")
    with open(output_file, 'w', newline='', encoding='utf-8') as filelist:
        csv_writer = csv.writer(filelist)
        csv_writer.writerow(['Path', 'Type'])  # Header

        for foldername, subfolders, filenames in os.walk(root_path, followlinks=False):
            try:
                for subfolder in subfolders:
                    folder_path = os.path.join(foldername, subfolder)
                    csv_writer.writerow([folder_path, 'Directory'])

                for filename in filenames:
                    file_path = os.path.join(foldername, filename)
                    csv_writer.writerow([file_path, 'File'])

            except Exception as e:
                print(f"Error processing folder {foldername}: {e}")

    filelist.close()

    # compressing file list to reduce overall file size of the triage output
    with zipfile.ZipFile("full_file_list.csv.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zip_filelist:
        zip_filelist.write("full_file_list.csv.txt")
    zip_filelist.close()
    os.rename(os.path.realpath('.') + "\\full_file_list.csv.zip", CASEFOLDER + "\\LiveResponseData\\filesystem" + "\\full_file_list.csv.zip")




def volatile_data_gather():
    """Gathers the volatile data"""
    print("\n[+] Gathering additional volatile data", flush=True)

    # grabbing host file
    hosts_file = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    hosts_file_dst = "{}/LiveResponseData/network/{}".format(CASEFOLDER, "hosts.txt")
    os.system("type {} > {}".format(hosts_file, hosts_file_dst))

    procs = [
        {'Command': "{}/pv.exe -m -e *".format(os.path.realpath('./prcview')), 'output': "Loaded_dlls.txt",
         'outdir': "/persistence/"},
        {'Command': "cmd.exe /C tasklist /SVC", 'output': "services_aw_processes.txt",
         'outdir': "/persistence/"},
        {'Command': "cmd.exe /C ipconfig /all", 'output': "Internet_settings.txt",
         'outdir': "/network/"},
        {'Command': "cmd.exe /C netstat -anbo", 'output': "Open_network_connections.txt",
         'outdir': "/network/"},
        {'Command': "cmd.exe /C ipconfig /displaydns", 'output': "DNS_cache.txt",
         'outdir': "/network/"},
        {'Command': "cmd.exe /C arp -a", 'output': "ARP.txt",
         'outdir': "/network/"},
        {'Command': "cmd.exe /C net user", 'output': "Local_user_list.txt",
         'outdir': "/user/"},
        {'Command': "cmd.exe /C netstat -rn", 'output': "routing_table.txt",
         'outdir': "/network/"},
        {'Command': "cmd.exe /C net sessions", 'output': "NetBIOS_sessions.txt",
         'outdir': "/network/"},
        {'Command': "cmd.exe /C net file", 'output': "NetBIOS_transferred_files.txt",
         'outdir': "/network/"},
        {'Command': "cmd.exe /C schtasks /query /fo LIST /v", 'output': "scheduled_tasks.txt",
         'outdir': "/persistence/"},
        {'Command': "cmd.exe /C systeminfo", 'output': "system_info.txt",
         'outdir': "/system/"},
        {'Command': "cmd.exe /C ver", 'output': "Windows_Version.txt",
         'outdir': "/system/"},
        {'Command': "cmd.exe /C dir /S /B /AHD C:\\Windows\\*",
         'output': "List_hidden_directories.txt", 'outdir': "/filesystem/"},
        {'Command': "{}\\system32\\chcp.com".format(os.getenv('WINDIR')),
         'output': "Windows_codepage.txt", 'outdir': "/system/"},
    ]

    for processes in procs:
        running_procs = processes['Command']
        with open(processes['output'], "w+") as fout:
            subprocess.call(running_procs, stdout=fout)
    for files in procs:
        os.rename(os.path.realpath('.') + "/" + files['output'],
                  CASEFOLDER + "/LiveResponseData" + files['outdir'] + files['output'])
        fout.close()


def get_process_info(process):
    try:
        process_info = {
            'PID': process.pid,
            'PPID': process.ppid(),
            'Name': process.name(),
            'User': process.username(),
            'Command': ' '.join(process.cmdline()),
            'Open Files': process.open_files()
        }
        return process_info
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def save_processes_to_csv(processes, csv_filename):
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['PID', 'PPID', 'Name', 'User', 'Command', 'Open Files']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for process in processes:
            process_info = get_process_info(process)
            if process_info:
                writer.writerow(process_info)


def dump_procs():
    print("\n[+] Exporting process details", flush=True)
    running_processes = psutil.process_iter(attrs=['pid', 'ppid', 'name', 'cmdline'])
    save_processes_to_csv(running_processes, 'running_processes.csv')
    proc_dest = CASEFOLDER + "\\LiveResponseData\\processes\\running_processes.csv"
    # moving prefetch info to case folder
    os.rename(os.path.realpath('.') + "/" + "running_processes.csv", proc_dest)


def user_account_report():
    # User details for local and domain user accounts
    print("[+] Pulling user account details\n", flush=True)
    UARDIR = os.path.realpath('.') + "/userprofilesview/"
    uar_dst = CASEFOLDER + "\\LiveResponseData\\user\\user_acct_report.txt"
    UARCMD = "{}userprofilesview.exe /stext {}".format(UARDIR, uar_dst)
    subprocess.call(UARCMD)


def network_data_gathering():
    """Get open TCP and UDP ports"""
    print("\n[+] Network information gathering", flush=True)
    print("\n\t" + "[-] Collecting currently open TCP/UDP ports", flush=True)
    # setting up variables to run cports with output parameters
    c_ports_run = CPORTSDIR + "cports.exe /shtml cports.html /sort 1 /sort ~'Remote Address'"
    c_ports_param = CASEFOLDER + "/LiveResponseData/network" + "/cports.html"
    c_ports_exe = c_ports_run + c_ports_param
    # executing cports
    subprocess.call(c_ports_exe)
    # moving cports output case folder
    os.rename(os.path.realpath('.') + "/" + "cports.html", CASEFOLDER +
              "/LiveResponseData/network" + "/" + "cports.html")
    print("\t" + "[-] Running WLAN Report\n", flush=True)
    if os.path.exists("C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\"):
        os.system("rd /s/q C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\")
        os.system("netsh wlan show wlanreport > nul")
        os.rename("C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\wlan-report-latest.html", CASEFOLDER +
              "/LiveResponseData/network/WLAN Report" + "/" + "wlan-report-latest.html")
        os.rename("C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\wlan-report-latest.xml", CASEFOLDER +
              "/LiveResponseData/network/WLAN Report" + "/" + "wlan-report-latest.xml")
        os.rename("C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\wlan-report-latest.cab", CASEFOLDER +
              "/LiveResponseData/network/WLAN Report" + "/" + "wlan-report-latest.cab")
    else:
        os.system("netsh wlan show wlanreport > nul")
        os.rename("C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\wlan-report-latest.html", CASEFOLDER +
              "/LiveResponseData/network/WLAN Report" + "/" + "wlan-report-latest.html")
        os.rename("C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\wlan-report-latest.xml", CASEFOLDER +
              "/LiveResponseData/network/WLAN Report" + "/" + "wlan-report-latest.xml")
        os.rename("C:\\ProgramData\\Microsoft\\Windows\\WlanReport\\wlan-report-latest.cab", CASEFOLDER +
              "/LiveResponseData/network/WLAN Report" + "/" + "wlan-report-latest.cab")


def external_ip():
    print("\t[-] Grabbing external IP address", flush=True)
    """Get public IP"""
    public_ip = pub_ip.get()
    with open("external_IP.txt", "w") as ipfout:
        ipfout.write("External host IP:\n")
        ipfout.write(public_ip)
    ipfout.close()
    os.rename(os.path.realpath('.') + "/" + "external_IP.txt", CASEFOLDER +
              "/LiveResponseData/network" + "/" + "external_IP.txt")


def fwlog_dump():
    """Dump Windows firewall config"""
    print("[+] Dumping Windows firewall config", flush=True)
    # setting up vars
    fw_cmd = os.system("netsh advfirewall show all >> firewall_config.txt")
    advfw_did = os.system("netsh advfirewall firewall show rule name=all dir=in type=dynamic >> firewall_config.txt")
    advfw_dod = os.system("netsh advfirewall firewall show rule name=all dir=out type=dynamic >> firewall_config.txt")
    advfw_dis = os.system("netsh advfirewall firewall show rule name=all dir=in type=static >> firewall_config.txt")
    advfw_dos = os.system("netsh advfirewall firewall show rule name=all dir=out type=static >> firewall_config.txt")
    os.rename(os.path.realpath('.') + "/" + "firewall_config.txt", CASEFOLDER + "/LiveResponseData/system" + "/" + "firewall_config.txt")


def windows_update_log():
    '''Convert ETL files to Windows Update log'''
    winuplog_src = "c:\\temp\\WindowsUpdate.log"
    winuplog_dst = CASEFOLDER + "\\LiveResponseData\\system\\WindowsUpdate.log"
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
            print("\n[!] Windows Update log was not generated correctly.", flush=True)
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
        ps_history_dst = CASEFOLDER + "\\LiveResponseData\\logs\\powershell_command_history_{}.txt".format(users)

        try:
            if os.path.isfile(ps_history_src):
                print("\t[+] Checking '{}' [OK]".format(users), flush=True)
                shutil.copy(ps_history_src, ps_history_dst)
            else:
                print("\t[-] Checking '{}' [NOT FOUND]".format(users), flush=True)
        except IOError as io_error_2:
            print(io_error_2)
            sys.exit("\n[!] Ouch! Something went wrong, but I'm not sure what :).")

    sys_pshf = "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
    ps_sys_history_dst = CASEFOLDER + "\\LiveResponseData\\logs\\powershell_command_history_SYSTEM.txt"

    if os.path.isfile(sys_pshf):
        print("\t[+] Checking 'SYSTEM' [OK]", flush=True)
        shutil.copy(sys_pshf, ps_sys_history_dst)
    else:
        print("\t[-] Checking 'SYSTEM' [NOT FOUND]", flush=True)


def system_data_gathering():
    """Gather system data"""
    # [BEGIN] System Data Gathering
    if ARGS.externalip:
        print("\n[+] Gathering system data\n", flush=True)
    else:
        print("[+] Gathering system data\n", flush=True)
    print("[+] Running Sysinternals tools\n", flush=True)
    print("\t[-] Accepting EULA", flush=True)
    print("\t[-] Executing toolset", flush=True)
    sys_internals_list = ['Autoruns', 'PsFile', 'PsLoggedOn',
                          'PsLogList', 'Tcpvcon', 'TCPView', 'Streams']

    for program in sys_internals_list:
        eula = "cmd.exe /C reg.exe ADD HKCU\\Software\\Sysinternals\\" + \
        program + " /v EulaAccepted /t REG_DWORD /d 1 /f"
        subprocess.call(eula, stdout=NOERROR, stderr=NOERROR)

    si_dir = os.path.realpath('.') + "\\sysinternals\\"

    # [autorunsc] setting up path to Sysinternals tools

    sys_proc = [
        {'Command': "autorunsc.exe", 'output': "autorunsc.txt",
         'outdir': "/persistence/"},
        {'Command': "psfile.exe", 'output': "psfile.txt", 'outdir': "/filesystem/"},
        {'Command': "PsLoggedon.exe", 'output': "PsLoggedon.txt", 'outdir':"/user/"},
        {'Command': "Tcpvcon.exe -a ", 'output': "Tcpvcon.txt", 'outdir':"/network/"},
        {'Command': "streams.exe  -s {}\\ ".format(os.getenv('WINDIR')),
         'output': "Alternate_data_streams.txt", 'outdir':"/filesystem/"}
    ]

    for sys_internals in sys_proc:
        sys_running_procs = si_dir + sys_internals['Command']
        with open(sys_internals['output'], "w+") as fout:
            subprocess.call(sys_running_procs, stdout=fout, stderr=NOERROR)
        os.rename(os.path.realpath('.') + "/" + sys_internals['output'],
                  CASEFOLDER + "/LiveResponseData" + sys_internals['outdir']
                  + sys_internals['output'])


def list_shadows():
    # Shadow copy info
    print("\n[+] Exporting shadow file data", flush=True)
    with open("shadow_files.txt", "w") as shd:
        subprocess.call("vssadmin list shadows", stdout=shd, stderr=NOERROR)
    shd.close()
    shadow_dst = CASEFOLDER + "\\LiveResponseData\\filesystem\\shadow_files.txt"
    os.rename(os.path.realpath('.') + "/" + "shadow_files.txt", shadow_dst)


def evtparseall():
    """Function to parse all events in the APP, SEC, SYS, & POWERSHELL event logs"""
    print("[+] Parsing all events in the APP, SEC, & SYS event logs\n", flush=True)
    # [psloglist] setting up path to EXE
    si_dir = os.path.realpath('.') + "\\sysinternals\\"
    si_psloglist_exe_path = si_dir + "psloglist.exe -accepteula"

    # [psloglist] setting parameters
    si_psloglist_app_param = " -s -x -nobanner application"
    si_psloglist_sec_param = " -s -x -nobanner security"
    si_psloglist_sys_param = " -s -x -nobanner system"
    si_psloglist_ps_param = ' -s -x -nobanner "Windows PowerShell"'

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
     CASEFOLDER + "/LiveResponseData/logs" + "/" + "eventlogs-all.csv")


def evtparse():
    """Function to collect event logs"""
    print("\n[+] Parsing key events from APP, SEC, SYS, & PowerShell\n", flush=True)
    si_dir = os.path.realpath('.') + "\\sysinternals\\"
    si_psloglist_app_evt_list = "1000,1001,1002,1022,1033,1034,1511,1518,11707,11708,11724"
    si_psloglist_sec_evt_list = "1102,4624,4625,4634,4647,4672,4648,\
4688,4697,4698,4699,4700,4701,4702,4720,4722,4724,4728,4732,\
4735,4738,4756,4776,4778,4779,4798,4799,4880,4881,4896,4898,5140,\
5145,7034,7036,7040,4649,4768,4769,4770,4771,4800,4801,4802,4803,4723,4725,\
4726,4727,4729,4731,4733,4737,4740,4741,4742,4743,4754,4755,4757,4764,\
4765,4766,4767,4780,4616,4821,4822,4823,4824,4886,4887,4899,4900,4713,4662"
    si_psloglist_sys_evt_list = "6,104,7035,7045"
    si_psloglist_ps_evt_list = "600,4103,4104,4105,4106"
    pslog_list = [
        {'Command': "psloglist.exe -accepteula -s -x -nobanner -i {} \
         Application".format(si_psloglist_app_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/logs/"},
        {'Command': "psloglist.exe -accepteula -s -x -nobanner -i {} \
         Security".format(si_psloglist_sec_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/logs/"},
        {'Command': "psloglist.exe -accepteula -s -x -nobanner -i {} \
         System".format(si_psloglist_sys_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/logs/"},
        {'Command': 'psloglist.exe -accepteula -s -x -nobanner -i {} \
         "Windows PowerShell"'.format(si_psloglist_ps_evt_list),
         'output': "eventlogs_key_events.csv", 'outdir':"/logs/"}
        ]
    for pslog in pslog_list:
        pslog_running_procs = pslog['Command']
        with open(pslog['output'], "a") as fout:
            subprocess.call(si_dir + pslog_running_procs, stdout=fout, stderr=subprocess.STDOUT, shell=True)
    os.rename(os.path.realpath('.') + "/" + pslog_list[0]['output'],
              CASEFOLDER + "/LiveResponseData" + pslog_list[0]['outdir'] + pslog_list[0]['output'])


    # Grabbing and parsing virtual drive operations event log
    vhd_logfile_src = "C:\\Windows\\System32\\Winevt\\Logs\\Microsoft-Windows-VHDMP-Operational.evtx"
    if not os.path.exists(vhd_logfile_src):
        no_vmount = CASEFOLDER + "/LiveResponseData/logs/" + "vhd_mount_log.txt"
        with open(no_vmount, "w") as no_vhd:
            no_vhd.write("No virtual drive mounts not found on this system.")
        no_vhd.close()
        print("[!] Skipping virtual drive mount info, no log found", flush=True)

    else:
        print("[+] Parsing virtual drive mounts", flush=True)
        vhd_log_cmd_dir = os.path.realpath('.') + "\\EvtxECmd\\"
        vhd_logfile_dst = os.path.realpath('.') + "\\Microsoft-Windows-VHDMP-Operational.evtx"
        shutil.copy2(vhd_logfile_src, vhd_logfile_dst)
        vhd_logfile = vhd_logfile_dst
        vhdoutput_dir1 = os.path.realpath('.')
        vhdoutput_file = "vhd_mount_log.csv"
        vhd_evtx_cmd = '{}evtxecmd.exe -f "{}" --inc 1 --csv {} --csvf {}'.format(vhd_log_cmd_dir, vhd_logfile, vhdoutput_dir1, vhdoutput_file)
        subprocess.call(vhd_evtx_cmd, stdout=NOERROR, stderr=subprocess.STDOUT, shell=True)
        os.rename(os.path.realpath('.') + "/" + "vhd_mount_log.csv",
                  CASEFOLDER + "/LiveResponseData" + "/logs/" + "vhd_mount_log.csv")



    # Grabbing and parsing Windows Firewall event log
    fw_log_cmd_dir = os.path.realpath('.') + "\\EvtxECmd\\"
    fw_logfile_src = "C:\\Windows\\System32\\Winevt\\Logs\\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
    print("\n[+] Parsing firewall events", flush=True)
    fw_logfile_dst = os.path.realpath('.') + "\\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx"
    shutil.copy2(fw_logfile_src, fw_logfile_dst)
    fw_logfile = fw_logfile_dst
    fwoutput_dir1 = os.path.realpath('.')
    fwoutput_file = "firewall_events.csv"
    fw_evtx_cmd = '{}evtxecmd.exe -f "{}" --inc 2004,2005,2006,2009,2033 --csv {} --csvf {}'.format(fw_log_cmd_dir, fw_logfile, fwoutput_dir1, fwoutput_file)
    subprocess.call(fw_evtx_cmd, stdout=NOERROR, stderr=subprocess.STDOUT, shell=True)
    os.rename(os.path.realpath('.') + "/" + "firewall_events.csv",
              CASEFOLDER + "/LiveResponseData" + "/logs/" + "firewall_events.csv")



    # Grabbing and parsing RDP Local Session Manager Operational event log
    evtxecmd_dir = os.path.realpath('.') + "\\EvtxECmd\\"
    rdp_logfile_src = "C:\\Windows\\System32\\Winevt\\Logs\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
    print("\n[+] Parsing RPD logon/logoff events", flush=True)
    rdp_logfile_dst = os.path.realpath('.') + "\\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"
    shutil.copy2(rdp_logfile_src, rdp_logfile_dst)
    rdp_logfile = rdp_logfile_dst
    output_dir1 = os.path.realpath('.')
    output_file = "rdp_logon_logoff_events.csv"
    rdp_evtx_cmd = '{}evtxecmd.exe -f "{}" --inc 21,23 --csv {} --csvf {}'.format(evtxecmd_dir, rdp_logfile, output_dir1, output_file)
    subprocess.call(rdp_evtx_cmd, stdout=NOERROR, stderr=subprocess.STDOUT, shell=True)
    os.rename(os.path.realpath('.') + "/" + "rdp_logon_logoff_events.csv",
              CASEFOLDER + "/LiveResponseData" + "/logs/" + "rdp_logon_logoff_events.csv")


def evtxall():
    """Function to pull full APP, SYS, SEC, Powershell, & Firewall event log (evtx) files"""
    print("[+] Grabbing App, Sys, Sec, Powershell, & Firewall (.evtx) files\n", flush=True)

    event_log_path = "C:\\Windows\\System32\\winevt\\Logs"
    event_log_dst = CASEFOLDER + "\\LiveResponseData\\logs"
    app_log_src = "{}\\Application.evtx".format(event_log_path)
    sys_log_src = "{}\\System.evtx".format(event_log_path)
    sec_log_src = "{}\\Security.evtx".format(event_log_path)
    ps_log_src = "{}\\Windows PowerShell.evtx".format(event_log_path)
    fw_log_src = "{}\\Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx".format(event_log_path)

    # executing file copy using shutil.copy2 in order to preserve file metadata
    shutil.copy2(app_log_src, event_log_dst)
    shutil.copy2(sys_log_src, event_log_dst)
    shutil.copy2(sec_log_src, event_log_dst)
    shutil.copy2(ps_log_src, event_log_dst)
    shutil.copy2(fw_log_src, event_log_dst)



def prefetch_p():
    """Parse the Prefetch"""
    # [BEGIN] Prefetch Parsing
    print("\n[+] Parsing prefetch data\n", flush=True)

    # [pf] setting up path to Eric Zimmermans tools
    pecmd_dir = os.path.realpath('.') + "\\PECmd\\"

    # [pf] setting up path to EXE and adding the -d option for directory
    pf_exe_path = pecmd_dir + "PECmd.exe -d  "

    # [pf] directory location of Prefetch files
    pf_directory = "{}\\LiveResponseData\\Prefetch\\raw".format(CASEFOLDER)

    # [pf] setting full pf.exe command with args
    pf_command = pf_exe_path + pf_directory

    # Execute the pf command and directing output to a file
    with open('parsed-prefetch.txt', 'w') as fout:
        subprocess.call(pf_command, stdout=fout)

    # moving prefetch info to case folder
    os.rename(os.path.realpath('.') + "/" + "parsed-prefetch.txt",
              CASEFOLDER + "\\LiveResponseData\\Prefetch\\parsed-prefetch.txt")


def registry_stuff():
    """[BEGIN] registry Extraction"""
    print("[+] Dumping & parsing registry hives\n", flush=True)
    registry_dump_hives = {"SAM": r'HKLM\SAM', "SYSTEM": r'HKLM\SYSTEM',
                           "SECURITY": r'HKLM\SECURITY', "SOFTWARE": r'HKLM\SOFTWARE'}
    for hive in registry_dump_hives:
        reg = "cmd.exe /C reg.exe SAVE " + registry_dump_hives[hive]
        reg_out = " " + CASEFOLDER + "\\LiveResponseData\\registry\\raw\\" + hive + " " + hive + ".hiv"
        reg_dump = reg + reg_out
        subprocess.call(reg_dump, stdout=NOERROR, stderr=NOERROR)
    # [END] registry Extraction

    # [BEGIN] registry Parsing
    # [Regripper] setting up path to Regripper
    rr_dir = os.path.realpath('.') + "\\regripper\\"

    # [Regripper] setting up path to EXE
    rr_exe_path = rr_dir + "rip.exe"

    # [Regripper] setting parameters
    registry_hives_os = ["SAM", "SYSTEM", "SECURITY", "SOFTWARE"]
    for hives in registry_hives_os:
        param_1 = " -r " + CASEFOLDER + "\\LiveResponseData\\registry\\" + hives + " -f " + hives
        reg_exec = rr_exe_path + param_1
        out_put_file = hives + "-parsed.txt"
        with open(out_put_file, 'w') as fout:
            subprocess.call(reg_exec, stdout=fout, stderr=NOERROR)
        os.rename(os.path.realpath('.') + "/" + out_put_file, CASEFOLDER +
                  "/LiveResponseData/registry" + "/" + out_put_file)

    # [Regripper] building user reg file list
    for root, dirs, files in os.walk(CASEFOLDER + "\\LiveResponseData\\registry\\raw"):
        registry_hives_users = [file for file in files if file.endswith(".DAT")]
        # [Regripper] processing user reg files with regripper
        for userreg in registry_hives_users:
            if "USRCLASS" in userreg:
                param_2 = " -r " + CASEFOLDER + "\\LiveResponseData\\registry\\" + userreg + " -f USRCLASS"
                reg_exec2 = rr_exe_path + param_2
                out_put_file2 = userreg + "-parsed.txt"
                with open(out_put_file2, 'w') as fout2:
                    subprocess.call(reg_exec2, stdout=fout2, stderr=NOERROR)
                fout2.close()
                os.rename(os.path.realpath('.') + "/" + out_put_file2, CASEFOLDER + "/LiveResponseData/registry" + "/" + out_put_file2)
            if "NTUSER" in userreg:
                param_3 = " -r " + CASEFOLDER + "\\LiveResponseData\\registry\\" + userreg + " -f NTUSER"
                reg_exec3 = rr_exe_path + param_3
                out_put_file3 = userreg + "-parsed.txt"
                with open(out_put_file3, 'w') as fout3:
                    subprocess.call(reg_exec3, stdout=fout3, stderr=NOERROR)
                fout3.close()
                os.rename(os.path.realpath('.') + "/" + out_put_file3, CASEFOLDER + "/LiveResponseData/registry" + "/" + out_put_file3)


def usb_ap():
    """Gather the USB artifacts"""
    # [BEGIN] USB Artifact Parsing
    print("[+] Grabbing USB logs\n", flush=True)

    # Detecting system architecture
    if os.path.exists("c:\\windows\\system32\\"):
        # variable to point to the location of "xcopy" on the remote system
        xcopy_dir = "c:\\windows\\system32\\"
        # setting up variables to run xcopy with appropriate parameters
        xcopy_param = xcopy_dir + "xcopy.exe C:\\Windows\\inf\\setupapi.*.log "
        xcopy_out = CASEFOLDER + "\\LiveResponseData\\usbdevices\\usb-install-logs"
        xcopy_usb = xcopy_param + xcopy_out

        # copying USB setup log from target
        subprocess.call(xcopy_usb, stdout=NOERROR, stderr=NOERROR)

    else:
        print("Xcopy missing from target", flush=True)


def log_total_runtime():
    runlog = CASEFOLDER + "\\runlog.txt"
    END_TIME = time.strftime("%H:%M:%S")
    etime = datetime.strptime(END_TIME, "%H:%M:%S")
    delta = etime - stime
    secs = delta.total_seconds()
    mins = secs / 60

    with open(runlog, "a+", newline="") as logupdate:
        logupdate.write('End time: ' + time.strftime("%m-%d-%Y %H:%M:%S") + '\n')
        logupdate.write('Total runtime: ' + str(mins) + ' minutes\n')

    logupdate.close()


def get_bitlocker():
    """Dumping bitlocker keys"""
    print("\n[+] Dumping bitlocker keys\n", flush=True)
    bl_dest = CASEFOLDER + "\\LiveResponseData\\system\\Bitlocker_key.txt"
    bl_cmd = "manage-bde -protectors C: -get >> Bitlocker_key.txt"

    # dumping bitlocker keys from target
    os.system(bl_cmd)

    # moving prefetch info to case folder
    os.rename(os.path.realpath('.') + "/" + "Bitlocker_key.txt", bl_dest)


def data_compress():
    """Log total runtime in runlog.txt"""
    log_total_runtime()

    """Allows compression for files """
    print("\n[+] Compressing triage output, please wait", flush=True)
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
    bhv_param = " /SaveDirect /sort 3 /VisitTimeFilterType 1 /cfg " + "BrowsingHistoryView.cfg /scomma " + CASEFOLDER + "/LiveResponseData/logs/BrowsingHistoryView.csv  "
    bhv_command = bhv_exe_path + bhv_param
    bhv_run = bhv_command
    subprocess.call(bhv_run, stderr=NOERROR)


def freespace_check(drive, minspace):
    """Check for free space on given drive"""
    usage = shutil.disk_usage(drive)
    if (usage.free // (2**30)) < minspace:  # the amount of free space required to get a full memory image in GB's
        if ARGS.memonly:
            print("\n[+] Checking free space", flush=True)
            print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
            print("\n\t[!] Disk space low on target, unable to dump memory. Please free up space on target and retry.", flush=True)
            env_cleanup()
            sys.exit()
        if ARGS.memory:
            print("\n[+] Checking free space", flush=True)
            print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
            print("\n\t[!] Disk space too low on target, unable to dump memory\n \n\t[!] Free up space or remove the -m argument and retry\n",
                flush=True)
            env_cleanup()
            sys.exit()
        if ARGS.pagefile:
            print("\n[+] Checking for additional free space for pagefile", flush=True)
            print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
            print("\n\t[!] Disk space too low on target, unable to grab pagefile file\n \n\t[!] Free up space or remove -p argument and retry\n", flush=True)
            env_cleanup()
            sys.exit()
        if ARGS.hiberfil:
            if os.path.isfile("C:\\hiberfil.sys"):
                print("\n[+] Checking for additional free space for hiberfil.sys", flush=True)
                print("\n\t[-] Free space is {} GB".format(usage.free // (2**30)), flush=True)
                print("\n\t[!] Disk space too low on target, unable to grab system files\n \n\t[!] Free up space or remove -hf argument and retry\n", flush=True)
                env_cleanup()
                sys.exit()
            else:
                no_file_out = CASEFOLDER + "/ForensicImages/system-files/" + "hiberfil.sys.txt"
                with open(no_file_out, "w") as no_file:
                    no_file.write("Hiberfil.sys not found on this system.")
                no_file.close()
                print("[!] Skipping hiberfil.sys collection, no file found\n", flush=True)

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
                scanlog_dst = "{}/LiveResponseData/logs/Windows_Defender_Scanlogs_{} \
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
        print("[+] Grabbing locked files from " + val + "\n", flush=True)
        files = ""
        file_list = "cmd.exe /C dir /a c:\\Users\\" + "\"" + val + "\"" + "\\" +"NTUSER.dat*" + " /b "
        all_ntuser_dat = subprocess.check_output(file_list, stderr=NOERROR, universal_newlines=True)
        list_of_files = all_ntuser_dat.rsplit("\n")
        fget_dir = os.path.realpath('.') + "\\FGET\\"
        for files in list_of_files:
            if files == "":
                pass
            else:
                fget_usrclass_output = CASEFOLDER + "/LiveResponseData/Registry/raw/" + val + "_" + "USRCLASS.DAT"
                fget_ntuser_output = CASEFOLDER + "/LiveResponseData/Registry/raw/" + "\"" + val + "\"" + "_" + files
                fget_exe_path = fget_dir + "FGET.exe -extract" + r' c:\Users\\' + "\"" + val + "\""+ "\\" + files + " " + fget_ntuser_output
                fget_exe_usrclass_path = fget_dir + "FGET.exe -extract" + " c:\\Users\\" + val + "\\AppData\\Local\\Microsoft\\Windows\\USRCLASS.DAT" + " " + fget_usrclass_output
                # Foresic copy of users NTUSER.DAT & USRCLASS.DAT
                subprocess.call(fget_exe_path, stdout=NOERROR, stderr=NOERROR)
                subprocess.call(fget_exe_usrclass_path, stdout=NOERROR, stderr=NOERROR)


def collect_hiberfil():
    """Using Fget to copy locked system files"""
    if os.path.isfile(CASEFOLDER + "/ForensicImages/system-files/" + "hiberfil.sys.txt"):
        pass

    else:
        print("[+] Collecting hiberfil.sys\n", flush=True)

        if COMPILED == 0:
            hiber_file = {"hiberfil.sys" : r'c:'}
        else:
            hiber_file = {"hiberfil.sys" : r'c:'}

        fget_dir = os.path.realpath('.') + "\\FGET\\"

        for hfile in hiber_file:
            col_hiber_file_output = CASEFOLDER + "/ForensicImages/system-files/" + hfile
            col_hiber_file_exe_path = fget_dir + "FGET.exe -extract" + " " + hiber_file[hfile] + "\\" + hfile + " " + col_hiber_file_output
            subprocess.call(col_hiber_file_exe_path, stdout=NOERROR, stderr=NOERROR)


def collect_pagefile():
    """Using Fget to copy locked system files"""
    if os.path.isfile("C:\\pagefile.sys"):
        print("[+] Collecting pagefile\n", flush=True)

        if COMPILED == 0:
            page_file = {"pagefile.sys" : r'c:'}
        else:
            page_file = {"pagefile.sys" : r'c:'}

        fget_dir = os.path.realpath('.') + "\\FGET\\"

        for pfile in page_file:
            col_pfile_output = CASEFOLDER + "/ForensicImages/system-files/" + pfile
            col_pfile_exe_path = fget_dir + "FGET.exe -extract" + " " + page_file[pfile] + "\\" + pfile + " " + col_pfile_output
            subprocess.call(col_pfile_exe_path, stdout=NOERROR, stderr=NOERROR)

    else:
        print("[+] Skipping pagefile collection, file not found on OS drive\n", flush=True)


def collect_srum():
    """Using Fget to copy locked system files"""
    print("[+] Collecting SRUM database\n", flush=True)

    if COMPILED == 0:
        srum_db = {"srudb.dat" : r'c:\windows\system32\sru'}
    else:
        if OSARCH == 64:
            srum_db = {"srudb.dat" : r'c:\windows\Sysnative\sru'}
        else:
            srum_db = {"srudb.dat" : r'c:\windows\system32\sru'}

    fget_dir = os.path.realpath('.') + "\\FGET\\"

    for sdb in srum_db:
        col_sdb_file_output = CASEFOLDER + "/ForensicImages/system-files/" + sdb
        col_sdb_file_exe_path = fget_dir + "FGET.exe -extract" + " " + srum_db[sdb] + "\\" + sdb + " " + col_sdb_file_output
        subprocess.call(col_sdb_file_exe_path, stdout=NOERROR, stderr=NOERROR)


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
    triage_acquistion_hash()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.pageonly:
    freespace_check("C:", 60)
    collect_pagefile()
    triage_acquistion_hash()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.hiberfonly:
    freespace_check("C:", 60)
    collect_hiberfil()
    triage_acquistion_hash()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.browserhistonly:
    get_browser_history()
    triage_acquistion_hash()
    data_compress()
    banner()
    sys.stdout.flush()
    env_cleanup()
    sys.exit(0)

if ARGS.pagefile:
    freespace_check("C:", 100)
    collect_pagefile()

if ARGS.hiberfil:
    freespace_check("C:", 100)
    collect_hiberfil()

if ARGS.srumdb:
    collect_srum()

if ARGS.memory:
    freespace_check("C:", 100)
    mem_scrape()

if ARGS.evtlogparseall:
    evtparseall()

if ARGS.evtlogfiles:
    evtxall()

pre_fetch()
powershell_history()
last_user()
USERS_LIST = list_users()

for user in USERS_LIST:
    fget_copy(user)

user_account_report()
fwlog_dump()
dump_procs()
generate_file_list("C:\\", "full_file_list.csv.txt")
volatile_data_gather()
network_data_gathering()

if ARGS.externalip:
    external_ip()

if ARGS.bitlocker:
    get_bitlocker()

system_data_gathering()
list_shadows()
windows_update_log()
get_defender_scanlogs()
evtparse()
prefetch_p()
registry_stuff()
usb_ap()
get_browser_history()

if ARGS.md5hash:
    hash_exes()

if ARGS.sha1hash:
    hash_exes()

if ARGS.sha256hash:
    hash_exes()

triage_acquistion_hash()
data_compress()
banner()
sys.stdout.flush()
env_cleanup()
sys.exit(0)
