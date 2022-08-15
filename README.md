# deauth_detector
This short script uses pyshark library to detect deauthentication packets while doing live sniffing

Used on Linux OS

Used an ALFA AWUS036ACH Wi-Fi USB receiver

Need to install pyshark library: pip install pyshark

http://kiminewt.github.io/pyshark/
https://github.com/KimiNewt/pyshark
https://pypi.org/project/pyshark/

Need to put ALFA on monitor mode
Step 1: Type "iwconfig" on Terminal to see the connected devices, can be under the name "wlan0"
Step 2: Type the following commands
  sudo ifconfig wlan0 down
  sudo iwconfig wlan0 mode monitor
  sudo ifconfig wlan0 up
Step 3: Type python detector.py
