---
title: PicoCTF 2019 - Shark on Wire 2
description: >-
  A medium-difficulty packet forensics writeup focused on extracting hidden data from UDP source ports.
author:
date: 2024-11-08 04:10:00 +0100
categories: [Writeup, CTF, Forensics]
tags: [picoctf, medium, picoctf-2019, forensics, ctf, networking, steganography, wireshark]
pin: false
math: true
---


## Introduction

This challenge provides a packet capture and asks us to recover a flag that was exfiltrated through the network. The interesting part is not hidden file recovery or a plain-text flag search, but recognizing that a protocol field is being used as a covert channel.

**Tools used**

- Wireshark
- NetworkMiner

When starting the challenge we get the following information regarding the CTF.

> We found this packet capture. Recover the flag that was pilfered from the network.
{: .prompt-info}

## Analysis

Initial inspection of `capture.pcap` did not reveal an obvious `picoCTF{...}` string. A Wireshark search for `udp contains "pico"` returned a few false positives, and NetworkMiner did not identify useful hidden files or credentials.

The traffic from source IP `10.0.0.6` to destination port `22` stood out. Frame `1104` contained the word `start`, frame `1303` contained `end`, and the packets between them carried repeated `\x61\x61\x61\x61\x61` values, or `aaaaa`, in the data field.

That pattern made the stream look deliberate. After inspecting each layer, the source port became the signal: every packet used a value where $$ n >= 5000 $$. The first and last packets used source port `5000`, while the packets in between varied.

## Hypothesis

The `start` and `end` markers suggest packet boundaries for an encoded message. Since the source ports are all offset from `5000`, subtracting `5000` from each non-marker source port should map the values into the readable ASCII range.

## Solution

The cleanest method is to treat each UDP source port as an integer, subtract `5000`, skip the marker value `0`, and convert the result to an ASCII character.

The following script extracts the hidden message:

```python
import sys
from scapy.all import *

packets = rdpcap(sys.argv[1])

flag = ""

for packet in packets:
    if packet.haslayer("UDP") and packet["UDP"].dport == 22 and packet.sport != 5000:
        flag += chr(packet.sport - 5000)

print(flag)
```

## Takeaway

When a capture has clear boundary markers but no obvious payload, inspect the metadata fields as carefully as the data field. Ports, sequence numbers, packet lengths, timing, and TTL values can all be used as low-effort covert channels.
