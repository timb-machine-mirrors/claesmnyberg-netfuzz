# Network Traffic Fuzzer
## ©️ 2014-2024 Claes M Nyberg, cmn@signedness.org

---
### --[ Table of contents

1 - Overview  

2 - Virtual Machines
>   2.1 - Fuzzbridge VM  
>   2.2 - OpenBSD Server  
>   2.3 - OpenBSD Client  

3 - Getting Started 
>   3.1 - Testing Netfuzz  
>   3.3 - Flipping Bits  

---
### --[ 1.0 - Overview
This is the second generation of the network fuzzer that began as a kernel patch to OpenBSD around 2012. 
This release is a set of kernel modules for FreeBSD where the pfil(9) hook is used to intercept and modify packets based on rules in a file (see netfuzz.rules.5).
Third generation is in beta testing and this release is no longer maintained but it is fully working and has been a valuable asset for finding bugs in many network protocol implementations.

I use this to get dumb fuzzing up and running really quick on all kind of devices.   
I sometimes run netfuzz on my gateway since I just have to use a simple BPF filter in the rules file to match the packets to fuzz,
but most of the times I flip bits in packets from hardware attached to a bridged physical interface, or a WiFi access point.

---
### --[ 2.1 - Fuzzbridge VM

```
Filename: fuzzbridge.ova
Username: root
Password: netfuzz
Hostname: fuzzbridge
```

This is a FreeBSD 10.3 i386 machine running the netfuzz kernel module along with the corresponding userland tools. 
The manuals are installed and are also available as PDF files in the man directory. 
The machine can be downloaded from the VMs directory.  

There are three network interfaces configured:

- Adapter 1 (em0 in machine)  
    This is a host only interface dedicated to administration through SSH.  
    IPv4: 192.168.56.120  
    ED25519 key fingerprint is SHA256:QlGHU3+fWINGaVr4Ew6HCIcoZkFbV165UJyybJ8QUV0  
    Log in as root with the password 'netfuzz'.  

- Adapter 2 (em1 in machine, renamed to fuzz0)  
    This interface is bridged to the host interface fuzz0 and  
    part of the bridge bridge0  

- Adapter 3 (em2 in machine, renamed to fuzz1)  
    This interface is bridged to the host interface fuzz1 and  
    part of the bridge bridge0  

The host interfaces fuzz0 and fuzz1 can be created as virtual interfaces in VirtualBox or as dummy interfaces  
on  Linux by running the ip command:  

```   
    # ip link add fuzz0 type dummy  
    # ifconfig fuzz0 up  
    # ip link add fuzz1 type dummy  
    # ifconfig fuzz1 up  
```

The virtual machine is configured to load the netfuzz kernel modules by default
and to setup a bridge between fuzz0 and fuzz1, allowing all traffic to flow.  
However, netfuzz is not enabled on boot and traffic will flow unmodified.  
More about enabling and writing rules below.  


### --[ 2.2 - OpenBSD Server
For the purpose of this tutorial, consider installing OpenBSD in a virtual machine and configure it as follows

- Adapter 1 (em0 in machine)  
    This is a host only interface dedicated to administration through SSH.  
    IPv4: 192.168.56.145  

- Adapter 2 (em1 in machine, bridged to fuzz1)  
    This interface is bridged to the host interface fuzz1 with  
        IPv4 192.168.168.10  
        IPv6 fd00:516:516::10  


### --[ 2.3 - OpenBSD Client
For the purpose of this tutorial, consider installing OpenBSD in a virtual machine and configure it as follows  

- Adapter 1 (em0 in machine)  
    This is a host only interface dedicated to administration through SSH.  
    IPv4: 192.168.56.144  
  
- Adapter 2 (em1 in machine, bridged to fuzz0)  
    This interface is bridged to the host interface fuzz0 with  
        IPv4 192.168.168.20  
        IPv6 fd00:516:516::20  
---
### --[ 3.1 - Testing Netfuzz

Start with logging into Fuzzbridge and making sure netfuzz is not enabled:
```
    user@workshop:~$ ssh root@192.168.56.120
	(root@192.168.56.120) Password for root@fuzzbridge:
	X11 forwarding request failed on channel 0
	Last login: Sun Sep 22 10:56:21 2024
	FreeBSD 10.3-RELEASE (GENERIC) #0 r297264: Fri Mar 25 03:51:29 UTC 2016

	Welcome to
	  ______             _          _     _
	 |  ____|           | |        (_)   | |
	 | |__ _   _ _______| |__  _ __ _  __| | __ _  ___
	 |  __| | | |_  /_  / '_ \| '__| |/ _` |/ _` |/ _ \
	 | |  | |_| |/ / / /| |_) | |  | | (_| | (_| |  __/
	 |_|   \__,_/___/___|_.__/|_|  |_|\__,_|\__, |\___|
    	                                     __/ |
	                                        |___/
	Copyright (c) Claes M Nyberg 2014, cmn@signedness.org

	This machine has the netfuzz suite of programs installed.
	More information available in the following manual pages:
		netfuzzctl.8
		netfuzz.rules.5
		netfuzz.4
		netfuzzlog.4
		(tcpdump.1 modified to include the log format)

    root@fuzzbridge:~ # netfuzzctl -d
    netfuzzctl: netfuzz not enabled
```
Log into both the OpenBSD NFS server and client (using the console or  
SSH to the host only interface). On the NFS server, start listening  
with nc(1) on port 516:
```
    user@workshop:~$ ssh root@192.168.56.145
    obsd.server# nc -vv -l 516
    Listening on 0.0.0.0 516
```
On the OpenBSD client, connect to the server using nc(1) on port 516
```
    user@workshop:~$ ssh root@192.168.56.144
    obsd.client# nc -vv 192.168.168.10 516
    Connection to 192.168.168.10 516 port [tcp/*] succeeded!
```
Send a few lines of text in either direction just to make sure that everything works.  
Let's also test that IPv6 is up and running by using ping6 to the server from the client:
```
    obsd.client# ping6 fd00:516:516::10
    PING fd00:516:516::10 (fd00:516:516::10): 56 data bytes
    64 bytes from fd00:516:516::10: icmp_seq=0 hlim=64 time=1.251 ms
    64 bytes from fd00:516:516::10: icmp_seq=1 hlim=64 time=0.413 ms
    64 bytes from fd00:516:516::10: icmp_seq=2 hlim=64 time=0.500 ms
    64 bytes from fd00:516:516::10: icmp_seq=3 hlim=64 time=0.378 ms
    64 bytes from fd00:516:516::10: icmp_seq=4 hlim=64 time=0.423 ms
    ^C
    --- fd00:516:516::10 ping statistics ---
    5 packets transmitted, 5 packets received, 0.0% packet loss
    round-trip min/avg/max/std-dev = 0.378/0.593/1.251/0.331 ms
    obsd.client#
```
Fuzzbridge is now verified to be running in between the client and server,  
acting as a transparent bridge, forwarding traffic in both directions.  
Please note that the bridge itself has the IPv4 address 192.168.168.254, 
and IPv6 fd00:516:516::254. 
We will need that if we want to inject packets later on (such as TCP RST) 
even though we are not actually using the adress of the bridge itself.

There is a simple rules file for netfuzz in /etc/netfuzz.rules, lets have a look at it:  
```
    root@fuzzbridge:~ # cat /etc/netfuzz.rules
    # Netfuzz rules.
    # The first rule that matches probabilistically
    # modifies the outgoing packet and the rest of the rules
    # are ignored. Note that you can have multiple
    # rules with the same packet filter and change
    # the probability to spread the rule used.
    # See netfuzz.rules.5
    #
    #
    # NOTE: There is a stupid bug in this version
    # that requires an empty line between rules.
    #

    # Drop approximately every fifth echo request packet
    drop all filter "icmp[icmptype] = icmp-echo" probability 5

    drop all filter "icmp6 and ip6[40]=128" probability 5

    # Duplicate icmp echo request packet
    dup all filter "icmp[icmptype] = icmp-echo" probability 5

    dup all filter "icmp6 and ip6[40]=128" probability 5

    # Replace a maximum of 10 'A's with 'B's
    # on approximately every other packet that matches the filter
    fuzz all filter "tcp port 516" \
        probability 2 \
        offset-start payload \
        offset-end packet-end  \
        rule bytereplace min 1 max 10 old 0x41 new 0x42


    root@fuzzbridge:~ #
```

We can see that the first and second rules will drop ICMP (IPv4 and IPv6)  
echo packets with a probability of 5, so on average every fifth packet  
will be dropped.  
Further on, reading the next two rules, on, average, every fifth ICMP  
echo packet will also be duplicated.  
And the last rule will replace some 'A' characters (0x41) with 'B' (0x42)  
for TCP connections using port 516 in any direction.  
Let's enable netfuzz on the bridge:  
```
    root@fuzzbridge:~ # netfuzzctl -f /etc/netfuzz.rules -e
    netfuzz enabled
    root@fuzzbridge:~ #
```
Now, if we send ICMP echo request packets (i.e. ping) from the client to server,  
we expect around every fifth packet to be either dropped or duplicated.  
Let's try it:
```
    obsd.client# ping 192.168.168.10
    PING 192.168.168.10 (192.168.168.10): 56 data bytes
    64 bytes from 192.168.168.10: icmp_seq=0 ttl=255 time=0.726 ms
    64 bytes from 192.168.168.10: icmp_seq=1 ttl=255 time=0.539 ms
    64 bytes from 192.168.168.10: icmp_seq=2 ttl=255 time=0.582 ms
    64 bytes from 192.168.168.10: icmp_seq=3 ttl=255 time=0.586 ms
    64 bytes from 192.168.168.10: icmp_seq=4 ttl=255 time=0.494 ms
    64 bytes from 192.168.168.10: icmp_seq=6 ttl=255 time=0.571 ms
    64 bytes from 192.168.168.10: icmp_seq=6 ttl=255 time=0.666 ms (DUP!)
    64 bytes from 192.168.168.10: icmp_seq=7 ttl=255 time=0.685 ms
    64 bytes from 192.168.168.10: icmp_seq=8 ttl=255 time=0.544 ms
    64 bytes from 192.168.168.10: icmp_seq=9 ttl=255 time=0.603 ms
    64 bytes from 192.168.168.10: icmp_seq=10 ttl=255 time=0.546 ms
    64 bytes from 192.168.168.10: icmp_seq=10 ttl=255 time=0.643 ms (DUP!)
    64 bytes from 192.168.168.10: icmp_seq=11 ttl=255 time=0.585 ms
    64 bytes from 192.168.168.10: icmp_seq=11 ttl=255 time=0.674 ms (DUP!)
    ^C
    --- 192.168.168.10 ping statistics ---
    13 packets transmitted, 11 packets received, 3 duplicates, 15.4% packet loss
    round-trip min/avg/max/std-dev = 0.494/0.603/0.726/0.064 ms
    obsd.client#
```
As we can tell from the output, netfuzz is working as expected. 
But let us run some IPv6 packets as well:

```
    obsd.client# ping6 fd00:516:516::10
    PING fd00:516:516::10 (fd00:516:516::10): 56 data bytes
    64 bytes from fd00:516:516::10: icmp_seq=0 hlim=64 time=0.679 ms
    64 bytes from fd00:516:516::10: icmp_seq=1 hlim=64 time=0.567 ms
    64 bytes from fd00:516:516::10: icmp_seq=2 hlim=64 time=0.610 ms
    64 bytes from fd00:516:516::10: icmp_seq=2 hlim=64 time=0.752 ms (DUP!)
    64 bytes from fd00:516:516::10: icmp_seq=3 hlim=64 time=0.569 ms
    64 bytes from fd00:516:516::10: icmp_seq=4 hlim=64 time=0.654 ms
    64 bytes from fd00:516:516::10: icmp_seq=4 hlim=64 time=0.753 ms (DUP!)
    64 bytes from fd00:516:516::10: icmp_seq=5 hlim=64 time=0.379 ms
    64 bytes from fd00:516:516::10: icmp_seq=6 hlim=64 time=0.597 ms
    64 bytes from fd00:516:516::10: icmp_seq=7 hlim=64 time=0.635 ms
    64 bytes from fd00:516:516::10: icmp_seq=7 hlim=64 time=0.729 ms (DUP!)
    64 bytes from fd00:516:516::10: icmp_seq=8 hlim=64 time=0.596 ms
    64 bytes from fd00:516:516::10: icmp_seq=9 hlim=64 time=0.576 ms
    64 bytes from fd00:516:516::10: icmp_seq=12 hlim=64 time=0.618 ms
    64 bytes from fd00:516:516::10: icmp_seq=13 hlim=64 time=0.615 ms
    ^C
    --- fd00:516:516::10 ping statistics ---
    14 packets transmitted, 12 packets received, 3 duplicates, 14.3% packet loss
    round-trip min/avg/max/std-dev = 0.379/0.622/0.753/0.089 ms
    obsd.client#
```

Seems to work as well. :)
Time to modify some TCP payload data! But first, lets run the modified  
tcpdump on the Fuzzbridge to watch what happens through the netfuzz log  
interface:  
```
root@fuzzbridge:~ # ifconfig netfuzzlog0 up
root@fuzzbridge:~ # tcpdump -vv -e -n -tttt -i netfuzzlog0
tcpdump: WARNING: netfuzzlog0: no IPv4 address assigned
tcpdump: listening on netfuzzlog0, link-type NETFUZZLOG (Netfuzz log), capture size 65535 bytes
```

Start the netcat listener on the server again:  
```
    obsd.server# nc -vv -l 516
    Listening on 0.0.0.0 516
```
And connect to it from the client:  
```
    obsd.client# nc -vv 192.168.168.10 516
    Connection to 192.168.168.10 516 port [tcp/*] succeeded!
```
Send a few lines of 'A' characters and see if the rule is applied, we  
might have to send a few lines to trigger the rule (probabilistic match):  

Client side:
```
    obsd.client# nc -vv 192.168.168.10 516
    Connection to 192.168.168.10 516 port [tcp/*] succeeded!
    AAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAA
```
Server side:
```
    obsd.server# nc -vv -l 516
    Listening on 0.0.0.0 516
    Connection received on 192.168.168.20 16268
    AAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAABABAAAABBBAAAAAABABA
    ABAAAAAAAAAAAAABABAAAAAAB
```
Fuzzbridge logger:  
```
    root@fuzzbridge:~ # tcpdump -vv -e -n -tttt -i netfuzzlog0
    tcpdump: WARNING: netfuzzlog0: no IPv4 address assigned
    tcpdump: listening on netfuzzlog0, link-type NETFUZZLOG (Netfuzz log), capture size 65535 bytes
    2024-08-26 10:33:57.927089
    NETFUZZ fuzz out on bridge0: rule 4 probability 2 offset 52-75 bytereplace 7 round(s) [55:0x41->0x42, 57:0x41->0x42, 62:0x41->0x42, 63:0x41->0x42, 6
    (tos 0x0, ttl 64, id 37949, offset 0, flags [DF], proto TCP (6), length 76)
        192.168.168.20.16268 > 192.168.168.10.516: Flags [P.], cksum 0x75e8 (correct), seq 3549985720:3549985744, ack 3544090936, win 256, options [nop,
    NETFUZZ original out on bridge0: rule 4 probability 2
    (tos 0x0, ttl 64, id 37949, offset 0, flags [DF], proto TCP (6), length 76)
        192.168.168.20.16268 > 192.168.168.10.516: Flags [P.], cksum 0x77ed (correct), seq 0:24, ack 1, win 256, options [nop,nop,TS val 2998470261 ecr
    2024-08-26 10:34:00.095493
    NETFUZZ fuzz out on bridge0: rule 4 probability 2 offset 52-77 bytereplace 4 round(s) [53:0x41->0x42, 67:0x41->0x42, 69:0x41->0x42, 76:0x41->0x42]
    (tos 0x0, ttl 64, id 39541, offset 0, flags [DF], proto TCP (6), length 78)
        192.168.168.20.16268 > 192.168.168.10.516: Flags [P.], cksum 0x22b1 (correct), seq 24:50, ack 1, win 256, options [nop,nop,TS val 2998472431 ecr
    NETFUZZ original out on bridge0: rule 4 probability 2
    (tos 0x0, ttl 64, id 39541, offset 0, flags [DF], proto TCP (6), length 78)
        192.168.168.20.16268 > 192.168.168.10.516: Flags [P.], cksum 0x23b4 (correct), seq 24:50, ack 1, win 256, options [nop,nop,TS val 2998472431 ecr
```
The output from the modified tcpdump displays the modified packet followed by the  
original, unmodified incoming packet. Watching the output from the logger we can  
see that the first time the rules hit, seven (7) 'A's was replaced with 'B' s at  
the given offsets after the '[', and the second time, there was four (4)  
replacements. You can read more about the log interface in netfuzzlog.4 and of  
course save the packets using the -w option in tcpdump as usual.  

### --[ 3.2 - Flipping Bits
Reading through the manual for netfuzz.rules (man netfuzz.rules) you can see  
that there are more rules defined as part of the EBNF, for example the bitflip rule.  
Let's modify the replace rule in /etc/netfuzz.rules to flip bits instead of replacing  
A characters with B and save it to the file /etc/netfuzz.rules.bitflip and restart netfuzz:  
```
    root@fuzzbridge:~ # cat /etc/netfuzz.rules.bitflipp

    # Bitflip every other TCP packets going to port 516
    fuzz all filter "tcp dst port 516" \
        probability 2 \
        offset-start payload \
        offset-end packet-end  \
        rule bitflip min 1 max 10

    root@fuzzbridge:~ # netfuzzctl -d
    netfuzz disabled
    root@fuzzbridge:~ # netfuzzctl -f /etc/netfuzz.rules.bitflipp -e
    netfuzz enabled
```


Now, continue to send lines from client to server (assuming you still have  
the nc up and running, otherwise restart it):  

Client side:
```
    obsd.client# nc -vv 192.168.168.10 516
    Connection to 192.168.168.10 516 port [tcp/*] succeeded!
    AAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAA
```

Server side:
```
    obsd.server# nc -vv -l 516
    Listening on 0.0.0.0 516
    Connection received on 192.168.168.20 16268
    AAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAABABAAAABBBAAAAAABABA
    ABAAAAAAAAAAAAABABAAAAAAB
    AAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAA
    AAQEAAA�AAAIAAAA�
    AAAAAAAAAAAAAAAAA
    AAQAAAAQMA@AAAA@@AA
```

As you can tell from the output, we are fuzzing!  
If you read through the netfuzz.rules manual (available as PDF in the man directory
or as a standard manual on the machine, "man netfuzz.rules"), you know that 
there are some pre-defined offset contstants that aid in computing dynamic 
locations in packets. In the example above we used 'payload' and 'packet-end', 
but there are also 'ip-header' and 'ip-payload' among others to simplify fuzzing  
of arbitrary protocols at somewhat dynamic locations. 

Have fun, and as always, behave!  
