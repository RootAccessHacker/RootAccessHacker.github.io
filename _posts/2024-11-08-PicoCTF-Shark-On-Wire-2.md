---
title: PicoCTF 2019 - Wire on Shark 2
description: >-
  In this forensics CTF we have to analyze a packet capture file. This CTF is of medium difficulty.
author:
date: 2024-11-08 04:10:00 +0100
categories: [Writeup, CTF]
tags: [picoctf, medium, PicoCTF 2019, forensics, ctf, networking, steganography]
pin: true
math: true
---


## Introduction

Tools used:
- Wireshark
- NetworkMiner

When starting the challenge we get the following information regarding the CTF.

> We found this packet capture. Recover the flag that was pilfered from the network.
{: .prompt-info}

## Analysis

Upon first inspection the capture.pcap file seemingly does not contain any immediately visible flag in the format picoCTF{...}. Aside from some false positives that arose after searching on: `udp contains "pico"`. I also tried to find some hidden files or credentials in the traffic with NetworkMiner but that didn't yield any results.

Eventually the traffic from src-IP: `10.0.0.6` with dst-port: `22` stood out; the first frame `1104` contained the word `start` and the last frame `1303` contained the word `end`. Whereas the frames in between contained `\x61\x61\x61\x61\x61` or `aaaaa` in their data-field. This lead me to think we might be on the right track.

After having inspected every layer of the packet, the source port number stood out. The value for each packet was:  $$ n >= 5000 $$. With the first and last frame being 5000, and the rest alternating values.

## Solution

After analysis it became clear that the UDP packets source port number, would result in a value that is within the range of readable ASCII-characters when truncated in the form: $$ n - 5000 $$. It would be possible to strip the prepending `5` or `50` as string, but the easiest would be to simply treat the values as integers and subtracting 5000, to afterwards convert them to characters.

The following script does all this and prints out the flag.

```python
import sys
from scapy.all import *

packets =  rdpcap(sys.argv[1])

flag = ""

for packet in packets:
    if packet.haslayer("UDP") and packet["UDP"].dport == 22 and packet.sport != 5000:
        flag += chr(packet.sport - 5000)

print(flag)
```

