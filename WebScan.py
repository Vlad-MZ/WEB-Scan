#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#   Script to WebScan
#

import os
import sys
import urllib.request
import urllib.error
import re
import argparse
import colorama

_author_ = "ZVM (01.11.2020)"
_version_ = "1.0"

# Colors.
#   The only ANSI sequences that Colorama converts into win32 calls are:
color = {
    # Fore (FOREGROUND):
    "FG_black":     "\033[30m",
    "FG_red":       "\033[31m",
    "FG_green":     "\033[32m",
    "FG_yellow":    "\033[33m",
    "FG_blue":      "\033[34m",
    "FG_magenta":   "\033[35m",
    "FG_cyan":      "\033[36m",
    "FG_white":     "\033[37m",
    "FG_reset":     "\033[37m",
    # Back (BACKGROUND):
    "BG_black":     "\033[40m",
    "BG_red":       "\033[41m",
    "BG_green":     "\033[42m",
    "BG_yellow":    "\033[43m",
    "BG_blue":      "\033[44m",
    "BG_magenta":   "\033[45m",
    "BG_cyan":      "\033[46m",
    "BG_white":     "\033[47m",
    "BG_reset":     "\033[47m",
    # Style:
    "reset_all":    "\033[0m",      # reset all (foreground and backround colors, and brightness)
    "bright":       "\033[;1m",     # bright
    "dim":          "\033[;2m",     # dim (looks same as normal brightness)
    "normal_brightness":"\033[;22m",# normal brightness
}


def clean():
    if "linux" in sys.platform:
        os.system("clear")
    elif "win" in sys.platform:
        os.system("cls")
    else:
        pass

def banner():
    print("")
    print("-------------" + color['FG_blue'] + color['bright'] +" Script to WEB scan " + color['reset_all'] + "--------------")
    print("       Developed by: ZVM (01.11.2020)        ")
    print("-------------------------------------------\n\n")
    print("")

def help():
    print("")
    print("color['FG_blue'] + color['bright'] + python WebScan.py --url <url-path> --dict <dictionary-file>" + color['reset_all'] + "\n")
    print("")

def validate_url(url_path):
    bc = True
    print(color['FG_green'] + "[+]" + color['FG_blue'] + color['bright'] + "Scanning...\n" + color['reset_all'])
    if not url_path.endswith("/"):
        url_path = url_path + "/"
    if not re.match('((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)', url_path):
        print(color['FG_red'] + color['bright'] + "\t Invalid URL !.." + color['reset_all'] + "\n")
        bc = False
    return bc

def validate_file(dictionary_file):
    bc = True
    if dictionary_file is not None:
        if not os.path.exists(dictionary_file) or not os.path.isfile(dictionary_file):
            print(color['FG_red'] + color['bright'] + "[!] Please check the file's Path for WordsList. It doesn't seem to be existed." + color['reset_all'])
            bc = False
    else:
        print(color['FG_red'] + color['bright'] + "[?] You didn't point  Dictionary File " + color['reset_all'])
        bc = False
    return bc

def scanWeb(url_path, dictionary_file):
    rela = []  # relationship
    avai = []  # available
    redi = []  # redirect

    with open(dictionary_file, 'r') as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith('###') or len(line) == 0:
                break
            try:
                connection_url = url_path + "{}".format(line)
                r = urllib.request.Request(connection_url)
                # UserAgent a la IE
                r.add_unredirected_header('User-Agent',
                                          'Mozilla/5.0 (Windows; U; Windows NT 6.0;en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6')
                r.add_unredirected_header('Referer', 'http://www.google.com/')
                with urllib.request.urlopen(r) as response:
                    the_page = response.read()
                    if response.getcode() == 200:
                        print(color['FG_red'] + color['bright'] + "[!] Found {}".format(connection_url) + color['reset_all'])
                        rela.append(connection_url + "   " + str(len(the_page)))
                    else:
                        print(color['FG_yellow'] + color['bright'] + "[!] Redirection {}".format(connection_url) + color['reset_all'])
                        redi.append(connection_url)
            except urllib.error.HTTPError as e:
                #print("The server couldn\'t fulfill the request.")
                #print("Error code: ", e.code)
                if e.code == 401:
                    print(color['FG_red'] + color['bright'] + "[!] Possible suspicion {}".format(connection_url) + color['reset_all'])
                    avai.append(connection_url)
                elif e.code == 404:
                    print(color['FG_green'] + color['bright'] + "[-] {}".format(connection_url) + color['reset_all'])
                elif e.code == 503:
                    print(color['FG_green'] + color['bright'] + "Not Found {}".format(connection_url) + color['reset_all'])
                else:
                    print(color['FG_yellow'] + color['bright'] + "[!] Redirection {}".format(connection_url) + color['reset_all'])
                    redi.append(connection_url)
            except urllib.error.URLError as e:
                print(e.reason)
                print(e)
        print("\n")

        print(color['FG_cyan'] + color['bright'] + "[!]" + " " + "Results" + color['reset_all'])
        if rela:
            print(color['FG_blue'] + color['bright'] + "[>]" + " " + color['FG_red'] + "Possible malicious files\n" + color['reset_all'])
            for relas in rela:
                print(color['FG_red'] + color['bright'] + "\t"  + relas + color['reset_all'])
            print(color['FG_blue'] + color['bright'] + '================================================================' + color['reset_all'])
        if avai:
            print(color['FG_blue'] + color['bright'] + "[+]" + " " + color['yellow'] + "Possible WebShell detected\n" + color['reset_all'])
            for avais in avai:
                print(avais)
            print(color['FG_blue'] + color['bright'] + '==================================================================' + color['reset_all'])
        if redi:
            print("Another incomings")
            for redis in redi:
                print(redis)
            print(color['FG_blue'] + color['bright'] + '===================================================================' + color['reset_all'])

def run(url_path, dictionary_file):
    try:
        banner()
        if validate_url(url_path) == False  or validate_file(dictionary_file) == False:
            help()
        else:
            scanWeb(url_path, dictionary_file)
    except KeyboardInterrupt:
        print(color['FG_red'] + color['bright'] + "Interrupted by user..." + color['reset_all'])
    except Exception as e:
        print(color['FG_red'] + color['bright'] + "Error: " + color['reset_all'] + "{}".format(e))


if __name__ == "__main__":
    colorama.init()
    parser = argparse.ArgumentParser('--url <url>' + '--dict <dictionary>')
    parser.add_argument('-u', '--url',  dest='url_path', required=False,
                        type=str, help='url path')
    parser.add_argument('-d', '--dict',  dest='dictionary', required=False,
                        type=str, help="path for dictionary file")
    args = parser.parse_args()

    url_path = args.url_path
    dictionary_file = args.dictionary

    if url_path is None:
        url_path = input("Insert URL #> ")
    if dictionary_file is None:
        dictionary_file = input("Insert path for dictionary file #> ")

    run(url_path, dictionary_file)



