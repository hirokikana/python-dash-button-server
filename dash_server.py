#!/usr/bin/python
#-*- coding:utf-8 -*-

from scapy.all import sniff
from ConfigParser import SafeConfigParser
import os

if __name__ == "__main__":
    config = SafeConfigParser()
    config.read('dash_server.conf')
    
    while(True):
        packet = sniff(filter="arp", count=1)[0]
        src_hw_addr = packet.src.upper()
        amazon_hw_addr_list = ["0C:47:C9",
                               "34:D2:70",
                               "40:B4:CD",
                               "44:65:0D",
                               "50:F5:DA",
                               "68:37:E9",
                               "68:54:FD",
                               "74:75:48",
                               "74:C2:46",
                               "84:D6:D0",
                               "88:71:E5",
                               "A0:02:DC",
                               "AC:63:BE",
                               "F0:27:2D",
                               "F0:D2:F1"]
        if len([x for x in amazon_hw_addr_list if src_hw_addr.startswith(x)]) > 0:
            if (src_hw_addr in config.sections()):
                exec_command = config.get(src_hw_addr, 'command')
                os.system(exec_command)
                print("execute command: %s" % exec_command)
            else:
                print("new Amazon Dash Button? %s" % src_hw_addr.upper())
    
