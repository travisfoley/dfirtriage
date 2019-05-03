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
## DESCRIPTION: Search tool for DFIRtriage output.                         ##
##                                                                         ##
## FILENAME: dtfind.py                                                     ##
## VERSION: 1.0                                                            ##
## STATUS: PUB                                                             ##
## AUTHORS: Travis Foley // Joel Maisenhelder                              ##
#############################################################################


# environment setup ------------------------------------------------------------------------------------------------------------#
import argparse, os, sys
from datetime import datetime

reg_files = ["NTUSER", "SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
version = "dtfind v1.0"
# environment setup ------------------------------------------------------------------------------------------------------------#


# commandline options ---------------------------------------------------------------------------------------------------------#
parser = argparse.ArgumentParser(description='DESCRIPTION: dtfind finds all instances of a given string in the DFIRTriage output and logs the findings.  dtfind can' 
' be ran from the commandline using the -kw argument or by executing and following the prompts.  the following chars are invalid:  * "" \ / ?', 
epilog='Example usage: dtfind.exe -kw "netcat"  OR  dtfind.exe -kw "program files"')
parser.add_argument('-kw', '--keyword', nargs="+", help="specify keyword string for search.")
args = parser.parse_args()
# commandline options ---------------------------------------------------------------------------------------------------------#


# banner ----------------------------------------------------------------------------------------------------------------------#
def banner():
    print('\n--------------------------')
    print('DFIRtriage Search Utility')
    print('      {}           '.format(version))
    print('--------------------------')
# banner ----------------------------------------------------------------------------------------------------------------------#


# establish key word if not entered on command line ---------------------------------------------------------------------------#
def get_keyword():
    global search_string
    search_string = input("\nEnter search term at the prompt.\n\n[dtfind]:> ")
    search_string = str(search_string)
# establish key word if not entered on command line ---------------------------------------------------------------------------#


# set path to LiveResponseData directory --------------------------------------------------------------------------------------#
def set_start_dir():
    global start_dir
    if "LiveResponseData" in os.getcwd():
        start_dir = os.getcwd()
    else:
        start_dir = input("\nEnter FULL path to 'LiveResponseData' dir (no quotes):> ")
        if "LiveResponseData" not in start_dir:
            sys.exit("\n-------------------------------------------------------------\n"
                "[!] LiveResponseData directory not found in path. Try again.\n"
                    "-------------------------------------------------------------")
        else:
            pass
            
# set path to LiveResponseData directory --------------------------------------------------------------------------------------#


# check search string for invalid characters ----------------------------------------------------------------------------------#
def search_string_check():
    global search_string
    bad_char = ['*', '""', '\\', '/', '?']
    for i in bad_char:
        if i in search_string:
            print("\n\n\t[!] SEARCH ERROR [!]\n")
            print("\n\tYou cannot use the following characters in your search string:  \n")
            print("\n\t {} \n".format(str(bad_char).strip("[]")))
            print("\n\tNOTE: All searches are wildcard searches.")
            print("\n\tIe. A search for the term 'badware' is the same as *badware*.  Any instance of the string "
                  "'badware' will be returned.")
            print("\n\n\t(Please retry your search.)\n")
            exit()
        else:
            continue
# check search string for invalid characters ----------------------------------------------------------------------------------#


# prints search results to console --------------------------------------------------------------------------#
def run_search():  
    print(start_dir)
    os.chdir(start_dir)
    global search_string
    search_list = search_file_list_no_highlight(curr_dir, search_string)
    for x in search_list:
        try:
            print("\n--------------------------------------------------------------------------------------------------"
                  "-----\n")
            print("Data File Name: ", x[0])
            print("Info: ", x[1])
            print("Line Number: ", x[2])
        except UnicodeEncodeError:
            continue
    log_file = "search_results({}).txt".format(search_string)
    print("\n=========================================================================================================="
          "=\n\n\nSearch complete. Your results have been saved in:  {}\n".format(log_file))

def search_file_list_no_highlight(filenamelist, searchString):
    global results
    results = []
    for filename in filenamelist:
        if filename.startswith(".\\Registry\\regripped-out\\rr."):
            with open(filename, encoding="UTF-8", errors="surrogateescape") as datafile:
                lineNum = 1
                for line in datafile:
                    if searchString in line:
                        results.append([filename, line.rstrip(), lineNum])
                    lineNum += 1
        elif searchString in open(filename, errors="surrogateescape").read():
            with open(filename, errors="surrogateescape") as datafile:
                lineNum = 1
                for line in datafile:
                    if searchString in line:
                        results.append([filename, line.rstrip(), lineNum])
                    lineNum += 1
        else:
            continue
    return results
# prints search results to console --------------------------------------------------------------------------#


# returns list containing full path to each file in current dir and all subdirs -----------------------------#
def get_file_list(dirPath):  
    fileList = []
    for dirname, dirnames, filenames in os.walk(dirPath):
        for filename in filenames:
            if filename.endswith(".exe"):
                break
            if filename.endswith(".pf"):
                break
            if "search_results" in filename:
                break
            if "dtfind." in filename:
                break
            for r in reg_files:
                if filename == r:
                    break
            else:
                fileList.append(os.path.join(dirname, filename))
    return fileList
# returns list containing full path to each file in current dir and all subdirs -----------------------------#


# writes results to log file with search term in name -------------------------------------------------------#
def log_results():
    ''' writes results to log file with search term in name ''' 
    global search_string
    log_file = "search_results({}).txt".format(search_string.replace(":", "."))
    search_list_log = search_file_list_no_highlight(curr_dir, search_string)
    original = sys.stdout
    sys.stdout = open(log_file, 'w', errors="surrogateescape")
    time_stamp = datetime.now().strftime('%m-%d-%Y %H:%M')
    print("# DFIR Triage Search LOG\n# dtfind v1.0\n# Time of search: {} \n# Keyword: '{}'\n".format(time_stamp, search_string))
    print("\n[BEGIN LOG]")
    for x in search_list_log:
        try:
            print("\n--------------------------------------------------------------------------------------------------"
                  "-----\n")
            print("Data File Name: ", x[0])
            print("Info: ", x[1])
            print("Line Number: ", x[2])
        except UnicodeEncodeError:
            continue
    print("\n\n[END LOG]")
    sys.stdout.close()
    sys.stdout = original
    os.startfile(".")
    sys.exit(0)
# writes results to log file with search term in name -------------------------------------------------------#


##########################################################################
################     All function calls defined above     ################
##########################################################################


# functions called everytime --------------------------------------------------------------------------------#
banner()
# functions called everytime --------------------------------------------------------------------------------#


# function order determined by commandline args -------------------------------------------------------------#
if not args.keyword:
    get_keyword()
    set_start_dir()
    curr_dir = get_file_list(start_dir)
    search_string_check()
    run_search()
    log_results()
else:
    # provides search term
    search_string = str(args.keyword).strip("['']")
    set_start_dir()
    curr_dir = get_file_list(start_dir)
    search_string_check()
    run_search()
    log_results()
# function order determined by commandline args -------------------------------------------------------------#