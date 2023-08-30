"""
Phishing Web Detector
By: Muhammad Abdullah
Coded In: Python3
Ver: 3.0
Email: mabdullahprogrammer@gmail.com
Git-Hub: https://github.com/mabdullahprogrammer/PhishDetector/
Original Concept By: Muhammad Abdullah
"""



print(""" ____  _     _     _     ____       _            _             
|  _ \| |__ (_)___| |__ |  _ \  ___| |_ ___  ___| |_ ___  _ __ 
| |_) | '_ \| / __| '_ \| | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
|  __/| | | | \__ \ | | | |_| |  __/ ||  __/ (__| || (_) | |   
|_|   |_| |_|_|___/_| |_|____/ \___|\__\___|\___|\__\___/|_|  
                                    """+"\x4d.\x41\x62\x64\x75\x6c\x6c\x61\x68")




url = input("Enter URL or Link: ")

if "https://" in url or "http://" in url:
    if '.html' in url or 'php' in url:
        print("The Website is phishing don't visit it!")
    elif 'http' in url and '.html' in url or '.php' in url:
        print("The website is both phishing and unsecure to use!")
    elif "http" in url:
        print("The Website Is Unsecure. Do not Visit it")
    elif 'https' in url and '.html' not in url or 'php' not in url and "http" not in url:
        print("Website is not phishing and is secure. Feel free to use it")
    elif "https" in url and '.html' not in url or '.php' not in url and 'http' not in url:
        print("Website is not phishing feel free to use it")
    elif 'https' in url:
        print("Website is secure and safe to use")
    else:
        print("Website cant be scanned!")
        print(" Your URL or Link should be incorrect")
        print(' If your link look likes this:-')
        print('         chrome://www.com')
        print('         192.168.0.1:https://www.example.com')
        print('         192.168.0.1:http://www.example.com')
        print(" so it can't be scanned with this type of scanner.")
else:
    print("Invalid URL")
