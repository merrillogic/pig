---
title: What?
layout: page
---

## What is PIG?

![Detective P.I.G.](img/pig.png)

PIG's input is essentially raw captured network data. From these raw packet files (called "pcap" files, for "packet capture") it reads the relevant data from each packet into a database. While it does this, an alternate process reads the newly input packets and sorts them into connections. A connection is a structure that represents all the packets sent from one machine to another. Within each connection, the packets are sent to all of the separate attack analyzers, which check them to see if they fit into suspicious patterns. The analyzers are essentially modified Finite State Automata, and simply check packets for specific criteria for each transition. If the analyzers do find attacks, they log the attack in the database. These attacks can then be viewed using the GUI.

## The Attacks

### SQL Injection

An SQL injection attack is an attack that attempts to make your server run the malicious user's evil SQL code. They do this by using your input forms on your websites as possible entry points. One way to detect them is to look for HTTP GET or POST requests that have SQL code or comments in them. If these packets are found, it's likely they are malicious. There is, of course, the possibility of falsely identifying benign packets in this manner, so keep that in mind. The easiest way to defend against SQL injection attacks is to sanitize all input received from external sources.

### Mail Denial of Service

The mail denial of service is an attack on a mail server intended to interrupt the reception of incoming mail.  This attack is detected by seeing if emails are coming in on one persistent connection at a fast rate, counting the number of emails and having a timeout where a new piece of mail has to come in by.  While this method of detection leads to very few false positive, considering in order to be detected as an attack, there needs to be at least 5 emails within 5 seconds, there will be false positive mainly because there are multiple ways to execute the attack.

### Password Cracking

Remote authentication password cracking is exactly what it sounds like: figuring out your password in order to impersonate you on any remote service.  The most common way of doing this is simply to try all combinations of known usernames and possible passwords (taken from dictionaries, lists of common passwords, or just looking at all possible character strings).  As such, password cracking detection relies on finding a series of many login attempts made from the same source to the same destination in a short period of time.  This leaves open the possibility of a slowed-down attack passing undetected, so know that this is a risk.  Preventing password cracking attacks can be as simple as limiting the number of consecutive failed login attempts allowed to any service you control.

### Denial of Service

A DoS attack is meant to overload a website or server, causing it to be unreachable by legitimate traffic. By causing a massive influx of packets to a server, an attacker can effectively knock a site or server offline. Since all attacks have this in common it is usually easy to check for. Blocking any IP address sending an extreme number of packets per second, or using special ports to enact the same effect, is an easy and effective method. There is more difficulty in dealing with Distributed or Low-Rate denial of service attacks, as the attackers don't send packets at a rate nearly as high as one would see in a normal DoS attack.

### Man in the Middle Attack

The idea behind a Man in the Middle Attack is pretty much what it sounds like. You have two computers attempting to communicate and a third computer gets in between them and attacks.

This works by exploiting weaknesses in the ARP protocol. The attacking computer sends ARP replies with incorrect an IP address/MAC address to both computers, who then communicate through the attacker. Once the attacker has done this, he or she can log, modify, or stop any traffic between the two computers.

This can be prevented or detected by storing all of the good ARP records and checking all packets for correct ARP records.
