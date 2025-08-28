from pskc import PSKC
from binascii import a2b_hex, b2a_hex

import random
import base64
import os
import platform
import re
import sys
import argparse
import subprocess

desc = 'Generates RFC6030 compliant pskc file and writes a HOTP based credential to the specified slot of the YubiKey.\r\nRequires the installation of YubiKey Manager.'
usagedesc = 'python3 yk-pskc.py -n [number of keys to write] -s [slot 1 or 2]\r\n' + desc + '\r\n\r\nExample: python3 yk-pskc.py -n 20 -s 1\r\n\r\n'

parser = argparse.ArgumentParser()
parser._action_groups.pop()
parser.usage = usagedesc
required = parser.add_argument_group('Required arguments')
required.add_argument('-n', '--numkeys', help='Number of keys to program', required=True)
required.add_argument('-s', '--slot', help='Slot 1 or 2 required (short or long touch of YubiKey)', required=True)
args = parser.parse_args()

if args.numkeys:
    iNumber = args.numkeys

if args.slot:
    iSlot = args.slot


def generate_b32(size=32, chars='ABCDEF' + '234567'):
    return ''.join(random.choice(chars) for _ in range(size))

def start_process():
    global iNumber, ykm_cmd, ykm_start, serialno, enchex, encsecret, iError, ykm_spc

    if platform.system() == 'Windows':
      ykm_cmd = "\"C:\Program Files\Yubico\YubiKey Manager\ykman.exe\""

    if platform.system() == 'Darwin':
      ykm_cmd = "/Applications/YubiKey\ Manager.app/Contents/MacOS/ykman"
      ykm_spc = "/Applications/YubiKey Manager.app/Contents/MacOS/ykman"

    ykm_start = os.popen(ykm_cmd + ' info').read()

    if ykm_start == '':
        print("YubiKey Manager was not detected on your system.  Please download from https://www.yubico.com/support/download/yubikey-manager/")
        print("If you are seeing this message before inserting a YubiKey, please insert initial key and re-start this process.")
        quit()
    
    iIndex = 1
    iError = 0

    enchex = generate_b32()
    encsecret = a2b_hex(enchex)
    
    print("WARNING: This process will overwrite each key inserted.\r\nPlease ensure the correct key is inserted during this batch programming process.\r\n")
    
    print("Programming will start for " + iNumber + " key(s).\r\n")

    input("Insert first YubiKey then press any key to continue.")

    while iIndex < int(iNumber) + 1:
       execcmd = pskc_start()
       
       iPtr = int(iNumber) - iIndex
       
       if iPtr > 0 and iError == 0:
         input("YubiKey " + str(serialno) + " configured, " + str(iPtr) + " remaining.\r\nInsert next YubiKey and press enter to continue.")
       else:
         iError =0

       iIndex += 1

    print("\r\n\r\nYubiKeys have been programmed and PSKC files exported in the current folder.\r\n")
    print("Press the gold y on the YubiKey during the enrollment process.\r\nThis will be used to activate the token during the third party import process\r\n")
    print("\r\nKey to unlock the .pskc files (please keep safe): " + enchex)

def pskc_start():
    global iNumber, ykm_cmd, ykm_start, serialno, enchex, encsecret, iError, ykm_spc

    yk_hex = generate_b32()

    b64 = base64.b32decode(yk_hex).hex()
    ba = bytearray.fromhex(b64)

    ykcmd = ykm_spc + ' info'
    ykm_start = subprocess.Popen(ykcmd, stdout=subprocess.PIPE)
    ykm_out, ykm_err = ykm_start.communicate()
   
    srl_start = ykm_start.find("number:")
    srl_end = ykm_start.find("Firmware version")

    serialno = ykm_start[srl_start +8:srl_end -1]

    if srl_end == -1:
        print ("No YubiKey was detected, please insert a YubiKey and start this script again.")
        quit()

    print ("Detected YubiKey, creating HOTP credential for serial number " + serialno)

    pskc = PSKC()

    pskc.encryption.setup_preshared_key(key=encsecret, fields='secret')

    key = pskc.add_key(
        id=serialno, serial=serialno, secret=bytes(ba), manufacturer='Yubico',
        response_length='6', algorithm = 'urn:ietf:params:xml:ns:keyprov:pskc:hotp')

    pskc.write(str(serialno) + '.pskc')

    subprocess.run([ykm_spc, 'otp', 'hotp', str(iSlot), yk_hex, '-f'], capture_output=True)

exec = start_process()
