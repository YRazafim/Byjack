# Byjack

> :warning: **Simple POC in Python to show TCP Hijacking for bypassing egress filtering**

> :warning: **Unfortunately It required administrator access on the victim**

## Scenario

- RCE through a vulnerability on a service available on TCP/&lt;Port&gt;.
- Egress filtering allow only established sessions on TCP to the Internet.
- Use TCP Hijacking to gain a stable access on the victim from the Internet by using the opened connection on the vulnerable service.

## Howto

- Launch **server.py** on attacker side and note TCP Sequence/Acknowledge number
- Launch **client.py** on victim side from the RCE to hijack TCP sessions and bypass firewall
