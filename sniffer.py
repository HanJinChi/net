from PyQt5 import QtWidgets
from PyQt5.QtCore import Qt,QFile,QObject,pyqtSignal
from PyQt5 import QtCore, QtGui, QtWidgets,uic
from PyQt5.QtWidgets import QTableWidgetItem
from threading import Thread
from scapy.all import *
import pcap
import dpkt
import socket
import datetime

class Signal(QObject):
    textPrint = pyqtSignal(list)

signal = Signal()
count = 0 

class Sniff:
    def __init__(self):
        self.ui = uic.loadUi("show.ui")
        self.ui.HTTP.setChecked(True)
        self.ui.TCP.setChecked(True)
        self.ui.UDP.setChecked(True)
        self.ui.ICMP.setChecked(True)
        self.ui.DNS.setChecked(True)
        self.ui.HTTPS.setChecked(True)
        self.ui.UNKNOWN.setChecked(True)
        self.ui.choice.addItems(pcap.findalldevs())
        self.ui.begin.clicked.connect(self.Begin)
        self.ui.stop.clicked.connect(self.Stop)
        self.ui.clear.clicked.connect(self.Clear)
        self.ui.display.clicked.connect(self.Print)
        self.Message = []        
        signal.textPrint.connect(self.Update)
        self.stop_thread = False
        
        
        
    def CheckNetOpen(self,net_type):
        if net_type == "HTTP" and self.ui.HTTP.isChecked() == True:
            return True
        elif net_type == "TCP" and self.ui.TCP.isChecked() == True:
            return True
        elif net_type == "UDP" and self.ui.UDP.isChecked() == True:
            return True
        elif net_type == "ICMP" and self.ui.ICMP.isChecked() == True:
            return True
        elif net_type == "DNS" and self.ui.DNS.isChecked() == True:
            return True
        elif net_type == "HTTPS" and self.ui.HTTPS.isChecked() == True:
            return True
        elif net_type == "UNKNOWN" and self.ui.UNKNOWN.isChecked() == True:
            return True
        else:
            return False
        
    def Begin(self):
        network_card = self.ui.choice.currentText()
        self.thread = Thread(target= self.SniffThread, args=(network_card,),daemon=True)
        print(f"NetWork Card is {network_card}")
        self.stop_thread = False
        self.thread.start()
        
        return     
    
    def Stop(self):
        self.stop_thread = True
        return
    
    def Clear(self):
        self.ui.display.setRowCount(0)
        self.Message = []
        return  
        
    def Update(self,message):
        count = self.ui.display.rowCount()
        self.ui.display.insertRow(count)
        self.ui.display.setItem(count,0,QTableWidgetItem(str(count+1)))
        self.ui.display.setItem(count,1,QTableWidgetItem(message[0]))
        self.ui.display.setItem(count,2,QTableWidgetItem(message[1]))
        self.ui.display.setItem(count,3,QTableWidgetItem(message[2]))
        self.ui.display.setItem(count,4,QTableWidgetItem(message[3]))
        self.ui.display.setItem(count,5,QTableWidgetItem(message[4]))
        self.ui.display.scrollToBottom()
        self.Message.append(message)
        
    def Print(self):
        count = self.ui.display.selectedItems()[0]
        self.ui.rowdata.setText(str(self.Message[count.row()][5]))
        self.ui.data.setText(self.Message[count.row()][6])
        
        
    def SniffThread(self,choice):
        sniffer = pcap.pcap(name = choice, promisc = True, immediate = True,timeout_ms = 50)
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
                    data_time = str(datetime.datetime.fromtimestamp(ts))
                    row_data = ip.pack()
                    hex_data = ' '.join(hex(byte)[2:].zfill(2) for byte in row_data)
                    if isinstance(ip.data, dpkt.icmp.ICMP):
                        src_socket = f"{socket.inet_ntoa(ip.src)}"
                        dst_socket = f"{socket.inet_ntoa(ip.dst)}"
                        net_type = "ICMP"
                    # 判断IP数据包的协议类型是否为TCP或UDP
                    if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
                        src_socket = f"{socket.inet_ntoa(ip.src)}:{ip.data.sport}"
                        dst_socket = f"{socket.inet_ntoa(ip.dst)}:{ip.data.dport}"
                        # 保存协议类型、源地址和端口号、目的地址和端口号
                        if ip.data.dport == 80 or ip.data.sport == 80:
                            net_type = "HTTP"
                        elif ip.data.dport == 443 or ip.data.sport == 443:
                            net_type = "HTTPS"
                        elif ip.data.dport == 53 or ip.data.sport == 53:
                            net_type = "DNS"
                        elif isinstance(ip.data, dpkt.tcp.TCP):
                            net_type = "TCP"
                        elif isinstance(ip.data, dpkt.udp.UDP):
                            net_type = "UDP"
                    else:
                        # 保存未知协议的IP数据包的来源地址和目的地址
                        net_type = "UNKNOWN"
                    if self.CheckNetOpen(net_type):
                        message = [data_time, src_socket, dst_socket, net_type, length, row_data, hex_data]  
                        signal.textPrint.emit(message)
                    if self.stop_thread == True:
                        break
            except Exception as e:
                print('Error:', e)

if __name__=="__main__":
    import sys
    app=QtWidgets.QApplication(sys.argv)
    ui = Sniff()    
    ui.ui.show()
    sys.exit(app.exec_())
