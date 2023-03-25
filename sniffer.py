from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt,QFile,QObject,pyqtSignal
from PyQt5 import QtCore, QtGui, QtWidgets,uic
from PyQt5.QtWidgets import QTableWidgetItem
import PyQt5
from threading import Thread
from multiprocessing import Process
from scapy.all import *
import pcap
import dpkt
import datetime
import os
import socket
import re
# 打开pcap文件


class Sniff:
    def __init__(self):
        self.ui = uic.loadUi("show.ui")
        self.ui.choice.addItems(pcap.findalldevs())
        self.ui.
        self.Message = []
        
        
    def SniffThread(self,choice):
        sniffer = pcap.pcap(name = choice,promisc=True, immediate=True,timeout_ms = 50)
        # 逐个读取数据包并解析
        for ts, buf in sniffer:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                # 判断以太网帧的类型是否为IP
                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    length = str(ip.len)
                    src_socket = ''
                    dst_socket = ''
                    net_type = ""
                    if isinstance(ip.data, dpkt.icmp.ICMP):
                        src_socket = f"{dpkt.inet_ntoa(ip.src)}"
                        dst_socket = f"{dpkt.inet_ntoa(ip.dst)}"
                        net_type = "ICMP"
                    # 判断IP数据包的协议类型是否为TCP或UDP
                    if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                        src_socket = f"{dpkt.inet_ntoa(ip.src)}:{ip.data.sport}"
                        dst_socket = f"{dpkt.inet_ntoa(ip.dst)}:{ip.data.dport}"
                        # 保存协议类型、源地址和端口号、目的地址和端口号
                        if ip.data.dport == 80 or ip.data.sport == 80:
                            net_type = "HTTP"
                        elif ip.data.dport == 443 or ip.data.sport == 443:
                            tls = dpkt.ssl.TLS(ip.data.data)
                            if tls.handshake:
                                net_type = "HTTPS"
                            else:
                                net_type = "unknown"
                        elif ip.data.dport == 53 or ip.data.sport == 53:
                            net_type = "DNS"
                        elif isinstance(ip.data, dpkt.tcp.TCP):
                            net_type = "TCP"
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            net_type = "UDP"
                    else:
                        # 保存未知协议的IP数据包的来源地址和目的地址
                        net_type = "unknown"
            except Exception as e:
                print('Error:', e)

if __name__=="__main__":
    import sys
    app=QtWidgets.QApplication(sys.argv)
    ui = Sniff()    
    ui.ui.show()
    sys.exit(app.exec_())
