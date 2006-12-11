#!/bin/sh

: ==== start ====

TZ=GMT export TZ

ipsec spi --clear
ipsec eroute --clear

enckey=0x4043434545464649494a4a4c4c4f4f515152525454575758
authkey=0x87658765876587658765876587658765

me=192.1.2.23
mine=192.0.2.0/24
him=192.1.2.45
his=192.0.1.0/24

#ipsec klipsdebug --set pfkey
#ipsec klipsdebug --set verbose

ipsec spi --af inet --edst $him --spi 0x5678 --proto comp --src $me --comp deflate

ipsec spi --af inet --edst $him --spi 0x12345678 --proto esp --src $me --esp 3des-md5-96 --enckey $enckey --authkey $authkey

ipsec spi --af inet --edst $him --spi 0x12345678 --proto tun --src $me --dst $him --ip4

ipsec spigrp inet $him 0x5678 comp    inet $him 0x12345678 esp 
ipsec spigrp inet $him 0x12345678 tun inet $him 0x5678 comp    

ipsec eroute --add --eraf inet --src $mine --dst $his --said tun0x12345678@$him

ipsec tncfg --attach --virtual ipsec0 --physical eth1
ifconfig ipsec0 inet $me netmask 0xffffff00 broadcast 192.1.2.255 up

arp -s $him 10:00:00:64:64:45
arp -s 192.1.2.254 10:00:00:64:64:45

ipsec look | sed -e "1d"

# magic route command
route add -host 192.0.1.1 gw $him dev ipsec0

: ==== end ====
