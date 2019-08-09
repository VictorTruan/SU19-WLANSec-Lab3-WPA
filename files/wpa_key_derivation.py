#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
- Derive WPA keys from Passphrase and 4-way handshake info

- Calculate an authentication MIC (the mic for data transmission uses the
Michael algorithm. In the case of authentication, we use SHA-1 or MD5)
"""

__author__      = "Abraham Rubinstein"
__maintainer__   = " Edin Mujkanovic, Taesuk Joung, Victor Truan"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2_math import pbkdf2_hex #contains function to calculate 4096 rounds on passphrase and SSID
import hmac, hashlib

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

# Read capture file -- it contains beacon, open authentication, associacion, 4-way handshake and data
wpa=rdpcap("wpa_handshake.cap") 


passPhrase  = "actuelle" #this is the passphrase of the WPA network
A           = "Pairwise key expansion" #this string is used in the pseudo-random function and should never be modified
#We got the ssid name from the first frame.
ssid = wpa[0].info

#Both client and AP are avalible in a lot of frame, we choose to take them from the first of the handshake.
APmac = a2b_hex(str.replace(wpa[5].addr2, ":", ""))
Clientmac = a2b_hex(str.replace(wpa[5].addr1, ":", ""))

# Authenticator and Supplicant Nonces
# The user send his nonce at the first message of the handshake and the AP send his during the second message.
ANonce = a2b_hex(b2a_hex(wpa[5].load)[26:90])
SNonce =  a2b_hex(b2a_hex(wpa[6].load)[26:90])

# This is the MIC contained in the 4th frame of the 4-way handshake. I copied it by hand.
# When trying to crack the WPA passphrase, we will compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = "36eef66540fa801ceee2fea9b7929b40"

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# We are getting a lot of informations from the last frame.
# The data so we can compute the MIC and the MIC so we can compare it.
# We don't recover the MIC here because we don't need it. It will be done in scaircrack.py
version = hex(wpa[8][EAPOL].version)[2:].zfill(2)
type = hex(wpa[8][EAPOL].type)[2:].zfill(2)
len = hex(wpa[8][EAPOL].len)[2:].zfill(4)
data = a2b_hex(version+type+len+b2a_hex(wpa[8].load)[:140]+"0"*50)
SNonce = b2a_hex(wpa[6].load)[26:90]

print "\n\nValues used to derivate keys"
print "============================"
print "Passphrase: ",passPhrase,"\n"
print "SSID: ",ssid,"\n"
print "AP Mac: ",b2a_hex(APmac),"\n"
print "CLient Mac: ",b2a_hex(Clientmac),"\n"
print "AP Nonce: ",b2a_hex(ANonce),"\n"
print "Client Nonce: ",b2a_hex(SNonce),"\n"

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
pmk = pbkdf2_hex(passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(a2b_hex(pmk),A,B)

#calculate our own MIC over EAPOL payload - The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)

#separate ptk into different keys - represent in hex
KCK = b2a_hex(ptk[0:16])
KEK = b2a_hex(ptk[16:32])
TK  = b2a_hex(ptk[32:48])
MICK = b2a_hex(ptk[48:64])

#the MIC for the authentication is actually truncated to 16 bytes (32 chars). SHA-1 is 20 bytes long.
MIC_hex_truncated = mic.hexdigest()[0:32]

print "\nResults of the key expansion"
print "============================="
print "PMK:\t\t",pmk,"\n"
print "PTK:\t\t",b2a_hex(ptk),"\n"
print "KCK:\t\t",KCK,"\n"
print "KEK:\t\t",KEK,"\n"
print "TK:\t\t",TK,"\n"
print "MICK:\t\t",MICK,"\n"
print "MIC:\t\t",MIC_hex_truncated,"\n"