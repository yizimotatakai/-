#coding: utf-8
from PyQt5 import QtCore,QtGui,QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from snifferui import *
from scapy.all import *
import os
import time
import multiprocessing
from scapy.layers import http
import numpy as np
import matplotlib.pyplot as plt
class SnifferThread(QtCore.QThread):
    HandleSignal = QtCore.pyqtSignal(scapy.layers.l2.Ether)
    def __init__(self,filter,iface):
        super().__init__()
        self.filter = filter
        self.iface = iface
    def run(self):
        sniff(filter=self.filter,iface=self.iface,prn=lambda x:self.HandleSignal.emit(x))
class pdfdumpThread(QtCore.QThread):
    pdfdumpSignal = QtCore.pyqtSignal(bool)
    def __init__(self,packet,path):
        super().__init__()
        self.packet = packet
        self.path = path
    def run(self):
        self.packet.pdfdump(self.path,layer_shift=1)
        self.pdfdumpSignal.emit(True)
class SnifferMainWindow(snifferui,QtWidgets.QMainWindow):
    filter = ""
    iface = ""
    packetList = []
    q = multiprocessing.Queue()
    def LookupIface(self):
        eth_local=[]
        a = repr(conf.route).split('\n')[1:]
        for x in a:
            b = re.search(r'[a-zA-Z](.*)[a-zA-Z]',x)
            eth_local.append(b.group())
        c = []
        c.append(eth_local[0])
        for i in range(0,len(eth_local),1):
            m = 0
            for j in range(0,len(c),1):
                if c[j] == eth_local[i]:
                    m += 1
            if m==0:
                c.append(eth_local[i])
        self.comboBoxIface.addItems(c)
    def __init(self):
        super(SnifferMainWindow,self).__init__()
    def setSlot(self):
        self.tableWidget.itemClicked.connect(self.clickInfo)
        self.tableWidget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tableWidget.customContextMenuRequested.connect(self.showContextMenu)
        self.contextMenu = QMenu(self.tableWidget)
        global count
        count = 0
        global display
        display = 0
        self.timer = QTimer(self)
        self.timer.start(1000)
        self.comboBoxIface = QComboBox()
        self.toolBar.addWidget(self.comboBoxIface)
        self.LookupIface()
        self.toolBar.setFixedWidth(1200)
        separator = QLabel()
        separator.setFixedWidth(500)
        self.toolBar.addWidget(separator)
        startAction = QAction('&开始',self)
        startAction.triggered.connect(self.Start)
        self.toolBar.addAction(startAction)
        separatorr = QLabel()
        separatorr.setFixedWidth(100)
        self.toolBar.addWidget(separatorr)
        stopAction = QAction('&停止',self)
        stopAction.triggered.connect(self.Stop)
        self.toolBar.addAction(stopAction)
    def showContextMenu(self,pos):
        self.contextMenu.exec_(QCursor.pos())
    def Start(self):
        global count
        count = 0
        global display
        display = 0
        self.packetList = []
        self.startTime = time.time()
        self.iface = self.comboBoxIface.currentText()
        self.tableWidget.setRowCount(0)
        self.tableWidget.removeRow(0)
        self.SnifferThread = SnifferThread(self.filter,self.iface)
        self.SnifferThread.HandleSignal.connect(self.display)
        self.SnifferThread.start()
    def setupUi(self, MainWindow):
        super(SnifferMainWindow, self).setupUi(MainWindow)
        self.tableWidget.insertColumn(7)
        self.tableWidget.setColumnHidden(7, True)
        self.tableWidget.horizontalHeader().setSectionsClickable(False)
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.setColumnWidth(0, 50)
        self.tableWidget.setColumnWidth(1, 150)
        self.tableWidget.setColumnWidth(2, 150)
        self.tableWidget.setColumnWidth(3, 150)
        self.tableWidget.setColumnWidth(4, 100)
        self.tableWidget.setColumnWidth(5, 100)
        self.tableWidget.setColumnWidth(6, 600)
        self.treeWidget.setHeaderHidden(True)
        self.treeWidget.setColumnCount(1)
    def display(self,packet):
        global count
        global display
        packetTime = '{:.7f}'.format(packet.time - self.startTime)
        type = packet.type
        if type == 0x800 :
            count += 1
            display = count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row,0, QtWidgets.QTableWidgetItem(str(count)))
            self.tableWidget.setItem(row,1,QtWidgets.QTableWidgetItem(str(packetTime)))
            self.tableWidget.setItem(row,2, QtWidgets.QTableWidgetItem(packet[IP].src))
            self.tableWidget.setItem(row,3, QtWidgets.QTableWidgetItem(packet[IP].dst))
            self.tableWidget.setItem(row,5, QtWidgets.QTableWidgetItem(str(len(packet))))
            self.tableWidget.setItem(row,7, QtWidgets.QTableWidgetItem(raw(packet).decode('Windows-1252','ignore')))
            if packet[IP].proto == 6:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('TCP'))
                if packet.haslayer('TCP'):
                    flag = ''
                    if packet[TCP].flags.A:
                        if flag == '':
                            flag += 'ACK'
                        else:
                            flag += ',ACK'
                    if packet[TCP].flags.R:
                        if flag == '':
                            flag += 'RST'
                        else:
                            flag += ',RST'
                    if packet[TCP].flags.S:
                        if flag == '':
                            flag += 'SYN'
                        else:
                            flag += ',SYN'
                    if packet[TCP].flags.F:
                        if flag == '':
                            flag += 'FIN'
                        else:
                            flag += ',FIN'
                    if packet[TCP].flags.U:
                        if flag == '':
                            flag += 'URG'
                        else:
                            flag += ',URG'
                    if packet[TCP].flags.P:
                        if flag == '':
                            flag += 'PSH'
                        else:
                            flag += ',PSH'
                    if flag == '':
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack,packet[TCP].window)))
                    else:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s [%s] Seq：%s Ack：%s Win：%s' % (packet[TCP].sport,packet[TCP].dport,flag,packet[TCP].seq,packet[TCP].ack,packet[TCP].window)))
            elif packet[IP].proto == 17:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('UDP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s -> %s 长度：%s' % (packet[UDP].sport,packet[UDP].dport,packet[UDP].len)))
            elif packet[IP].proto == 1:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ICMP'))
                if packet.haslayer('ICMP'):
                    if packet[ICMP].type == 8:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) request id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    elif packet[ICMP].type == 0:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Echo (ping) reply id：%s seq：%s' % (packet[ICMP].id,packet[ICMP].seq)))
                    else:
                        self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('type：%s id：%s seq：%s' % (packet[ICMP].type,packet[ICMP].id,packet[ICMP].seq)))
            elif packet[IP].proto == 2:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('IGMP'))
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem(''))
            else:
                self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem(str(packet[IP].proto)))
            self.packetList.append(packet)
        elif type == 0x806 :
            count += 1
            display = count
            row = self.tableWidget.rowCount()
            self.tableWidget.insertRow(row)
            self.tableWidget.setItem(row,0, QtWidgets.QTableWidgetItem(str(count)))
            self.tableWidget.setItem(row,1,QtWidgets.QTableWidgetItem(str(packetTime)))
            self.tableWidget.setItem(row,2, QtWidgets.QTableWidgetItem(packet[ARP].psrc))
            self.tableWidget.setItem(row,3, QtWidgets.QTableWidgetItem(packet[ARP].pdst))
            self.tableWidget.setItem(row,4, QtWidgets.QTableWidgetItem('ARP'))
            self.tableWidget.setItem(row,5, QtWidgets.QTableWidgetItem(str(len(packet))))
            if packet[ARP].op == 1:
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('Who has %s? Tell %s' % (packet[ARP].pdst,packet[ARP].psrc)))
            elif packet[ARP].op == 2:
                self.tableWidget.setItem(row,6, QtWidgets.QTableWidgetItem('%s is at %s' % (packet[ARP].psrc,packet[ARP].hwsrc)))
            self.tableWidget.setItem(row,7, QtWidgets.QTableWidgetItem(raw(packet).decode('Windows-1252','ignore')))
            self.packetList.append(packet)
    def Stop(self):
        self.SnifferThread.terminate()
    def clickInfo(self):
        row = self.tableWidget.currentRow()
        p = self.tableWidget.item(row,7).text()
        packet = scapy.layers.l2.Ether(p.encode('Windows-1252'))
        num = self.tableWidget.item(row,0).text()
        Time = self.tableWidget.item(row,1).text()
        length = self.tableWidget.item(row,5).text()
        iface = self.iface
        import time
        timeformat = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(packet.time))
        self.treeWidget.clear()
        self.treeWidget.setColumnCount(1)
        Ethernet = QtWidgets.QTreeWidgetItem(self.treeWidget)
        Ethernet.setText(0,'Ethernet，源MAC地址：'+ packet.src + '，目的MAC地址：'+packet.dst)
        EthernetDst = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetDst.setText(0,'目的MAC地址：'+ packet.dst)
        EthernetSrc = QtWidgets.QTreeWidgetItem(Ethernet)
        EthernetSrc.setText(0,'源MAC地址：'+ packet.src)
        try:
            type = packet.type
        except:
            type = 0
        if type == 0x800 :
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet)
            EthernetType.setText(0,'协议类型：IPv4(0x800)')
            IPv4 = QtWidgets.QTreeWidgetItem(self.treeWidget)
            IPv4.setText(0,'IPv4，源地址：'+packet[IP].src+'，目的地址：'+packet[IP].dst)
            IPv4Version = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Version.setText(0,'版本：%s'% packet[IP].version)
            IPv4Ihl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ihl.setText(0,'包头长度：%s' % packet[IP].ihl)
            IPv4Tos = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Tos.setText(0,'服务类型：%s'% packet[IP].tos)
            IPv4Len = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Len.setText(0,'总长度：%s' % packet[IP].len)
            IPv4Id = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Id.setText(0,'标识：%s' % packet[IP].id)
            IPv4Flags = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Flags.setText(0,'标志：%s' % packet[IP].flags)
            IPv4Frag = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4FlagsDF = QtWidgets.QTreeWidgetItem(IPv4Flags)
            IPv4FlagsDF.setText(0,'不分段：%s' % packet[IP].flags.DF)
            IPv4FlagsMF = QtWidgets.QTreeWidgetItem(IPv4Flags)
            IPv4FlagsMF.setText(0,'更多分段：%s' % packet[IP].flags.MF)
            IPv4Frag.setText(0,'片位移：%s ' % packet[IP].frag)
            IPv4Ttl = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Ttl.setText(0,'ttl：%s' % packet[IP].ttl)
            if packet[IP].proto == 6:
                if packet.haslayer('TCP'):
                    IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                    IPv4Proto.setText(0,'协议类型：TCP(6)')
                    tcp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                    tcp.setText(0,'TCP，源端口：%s，目的端口：%s，Seq：%s，Ack：%s' % (packet[TCP].sport,packet[TCP].dport,packet[TCP].seq,packet[TCP].ack))
                    tcpSport = QtWidgets.QTreeWidgetItem(tcp)
                    tcpSport.setText(0,'源端口：%s' % packet[TCP].sport)
                    tcpDport = QtWidgets.QTreeWidgetItem(tcp)
                    tcpDport.setText(0,'目的端口：%s' % packet[TCP].dport)
                    tcpSeq = QtWidgets.QTreeWidgetItem(tcp)
                    tcpSeq.setText(0,'Seq：%s' % packet[TCP].seq)
                    tcpAck = QtWidgets.QTreeWidgetItem(tcp)
                    tcpAck.setText(0,'Ack：%s' % packet[TCP].ack)
                    tcpDataofs = QtWidgets.QTreeWidgetItem(tcp)
                    tcpDataofs.setText(0,'数据偏移：%s' % packet[TCP].dataofs)
                    tcpReserved = QtWidgets.QTreeWidgetItem(tcp)
                    tcpReserved.setText(0,'保留：%s' % packet[TCP].reserved)
                    tcpFlags = QtWidgets.QTreeWidgetItem(tcp)
                    tcpFlags.setText(0,'标志：%s' % packet[TCP].flags)
                    tcpFlagsACK = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsACK.setText(0,'ACK：%s' % packet[TCP].flags.A)
                    tcpFlagsRST = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsRST.setText(0,'RST：%s' % packet[TCP].flags.R)
                    tcpFlagsSYN = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsSYN.setText(0,'SYN：%s' % packet[TCP].flags.S)
                    tcpFlagsFIN = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsFIN.setText(0,'FIN：%s' % packet[TCP].flags.F)
                    tcpFlagsURG = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsURG.setText(0,'紧急指针：%s' % packet[TCP].flags.U)
                    tcpFlagsPSH = QtWidgets.QTreeWidgetItem(tcpFlags)
                    tcpFlagsPSH.setText(0,'非缓冲区：%s' % packet[TCP].flags.P)
                    tcpWindow = QtWidgets.QTreeWidgetItem(tcp)
                    tcpWindow.setText(0,'窗口：%s' % packet[TCP].window)
                    tcpChksum = QtWidgets.QTreeWidgetItem(tcp)
                    tcpChksum.setText(0,'校验和：0x%x' % packet[TCP].chksum)
                    tcpUrgptr = QtWidgets.QTreeWidgetItem(tcp)
                    tcpUrgptr.setText(0,'紧急指针：%s' % packet[TCP].urgptr)
                    tcpOptions = QtWidgets.QTreeWidgetItem(tcp)
                    tcpOptions.setText(0,'选项：%s' % packet[TCP].options)
            elif packet[IP].proto == 17:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型：UDP(17)')
                udp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                udp.setText(0,'UDP，源端口：%s，目的端口：%s'% (packet[UDP].sport , packet[UDP].dport))
                udpSport = QtWidgets.QTreeWidgetItem(udp)
                udpSport.setText(0,'源端口：%s' % packet[UDP].sport)
                udpDport = QtWidgets.QTreeWidgetItem(udp)
                udpDport.setText(0,'目的端口：%s' % packet[UDP].dport)
                udpLen = QtWidgets.QTreeWidgetItem(udp)
                udpLen.setText(0,'长度：%s' % packet[UDP].len)
                udpChksum = QtWidgets.QTreeWidgetItem(udp)
                udpChksum.setText(0,'校验和：0x%x' % packet[UDP].chksum)
                if packet.haslayer('DNS'):
                    pass
            elif packet[IP].proto == 1:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型：ICMP(1)')
                icmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                icmp.setText(0,'ICMP')
                icmpType = QtWidgets.QTreeWidgetItem(icmp)
                if packet[ICMP].type == 8:
                    icmpType.setText(0,'类型：%s (Echo (ping) request)' % packet[ICMP].type)
                elif packet[ICMP].type == 0:
                    icmpType.setText(0,'类型：%s (Echo (ping) reply)' % packet[ICMP].type)
                else:
                    icmpType.setText(0,'类型：%s' % packet[ICMP].type)
                icmpCode = QtWidgets.QTreeWidgetItem(icmp)
                icmpCode.setText(0,'代码：%s' % packet[ICMP].code)
                icmpChksum = QtWidgets.QTreeWidgetItem(icmp)
                icmpChksum.setText(0,'校验和：0x%x' % packet[ICMP].chksum)
                icmpId = QtWidgets.QTreeWidgetItem(icmp)
                icmpId.setText(0,'标识：%s' % packet[ICMP].id)
                icmpSeq = QtWidgets.QTreeWidgetItem(icmp)
                icmpSeq.setText(0,'seq：%s' % packet[ICMP].seq)
                icmpTs_ori = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_ori.setText(0,'ts_ori：%s' % packet[ICMP].ts_ori)
                icmpTs_rx = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_rx.setText(0,'ts_rx：%s' % packet[ICMP].ts_rx)
                icmpTs_tx = QtWidgets.QTreeWidgetItem(icmp)
                icmpTs_tx.setText(0,'ts_tx：%s' % packet[ICMP].ts_tx)
                icmpGw = QtWidgets.QTreeWidgetItem(icmp)
                icmpGw.setText(0,'gw：%s' % packet[ICMP].gw)
                icmpPtr = QtWidgets.QTreeWidgetItem(icmp)
                icmpPtr.setText(0,'ptr：%s' % packet[ICMP].ptr)
                icmpReserved = QtWidgets.QTreeWidgetItem(icmp)
                icmpReserved.setText(0,'reserved：%s' % packet[ICMP].reserved)
                icmpLength = QtWidgets.QTreeWidgetItem(icmp)
                icmpLength.setText(0,'length：%s' % packet[ICMP].length)
                icmpAddr_mask = QtWidgets.QTreeWidgetItem(icmp)
                icmpAddr_mask.setText(0,'addr_mask：%s' % packet[ICMP].addr_mask)
                icmpnexthopmtu = QtWidgets.QTreeWidgetItem(icmp)
                icmpnexthopmtu.setText(0,'nexthopmtu：%s' % packet[ICMP].nexthopmtu)
            elif packet[IP].proto == 2:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型：IGMP(2)')
                igmp = QtWidgets.QTreeWidgetItem(self.treeWidget)
                igmp.setText(0,'IGMP')
                igmpCopy_flag = QtWidgets.QTreeWidgetItem(igmp)
                igmpCopy_flag.setText(0,'copy_flag：%s' % packet[IPOption_Router_Alert].copy_flag)
                igmpOptclass = QtWidgets.QTreeWidgetItem(igmp)
                igmpOptclass.setText(0,'optclass：%s' % packet[IPOption_Router_Alert].optclass)
                igmpOption = QtWidgets.QTreeWidgetItem(igmp)
                igmpOption.setText(0,'option：%s' % packet[IPOption_Router_Alert].option)
                igmpLength = QtWidgets.QTreeWidgetItem(igmp)
                igmpLength.setText(0,'length：%s' % packet[IPOption_Router_Alert].length)
                igmpAlert = QtWidgets.QTreeWidgetItem(igmp)
                igmpAlert.setText(0,'alert：%s' % packet[IPOption_Router_Alert].alert)
            else:
                IPv4Proto = QtWidgets.QTreeWidgetItem(IPv4)
                IPv4Proto.setText(0,'协议类型：%s'% packet[IP].proto)
            IPv4Chksum = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Chksum.setText(0,'校验和：0x%x' % packet[IP].chksum)
            IPv4Src = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Src.setText(0,'源IP地址：%s' % packet[IP].src)
            IPv4Dst = QtWidgets.QTreeWidgetItem(IPv4)
            IPv4Dst.setText(0,'目的IP地址：%s' % packet[IP].dst)
        elif type == 0x806 :
            EthernetType = QtWidgets.QTreeWidgetItem(Ethernet)
            EthernetType.setText(0,'协议类型：ARP(0x806)')
            arp = QtWidgets.QTreeWidgetItem(self.treeWidget)
            arp.setText(0,'ARP')
            arpHwtype = QtWidgets.QTreeWidgetItem(arp)
            arpHwtype.setText(0,'硬件类型：0x%x' % packet[ARP].hwtype)
            arpPtype = QtWidgets.QTreeWidgetItem(arp)
            arpPtype.setText(0,'协议类型：0x%x' % packet[ARP].ptype)
            arpHwlen = QtWidgets.QTreeWidgetItem(arp)
            arpHwlen.setText(0,'硬件地址长度：%s' % packet[ARP].hwlen)
            arpPlen = QtWidgets.QTreeWidgetItem(arp)
            arpPlen.setText(0,'协议长度：%s' % packet[ARP].plen)
            arpOp = QtWidgets.QTreeWidgetItem(arp)
            if packet[ARP].op == 1:
                arpOp.setText(0,'操作类型：request (%s)' % packet[ARP].op)
            elif packet[ARP].op == 2:
                arpOp.setText(0,'操作类型：reply (%s)' % packet[ARP].op)
            else:
                arpOp.setText(0,'操作类型：%s' % packet[ARP].op)
            arpHwsrc = QtWidgets.QTreeWidgetItem(arp)
            arpHwsrc.setText(0,'源MAC地址：%s' % packet[ARP].hwsrc)
            arpPsrc = QtWidgets.QTreeWidgetItem(arp)
            arpPsrc.setText(0,'源IP地址：%s' % packet[ARP].psrc)
            arpHwdst = QtWidgets.QTreeWidgetItem(arp)
            arpHwdst.setText(0,'目的MAC地址：%s' % packet[ARP].hwdst)
            arpPdst = QtWidgets.QTreeWidgetItem(arp)
            arpPdst.setText(0,'目的IP地址：%s' % packet[ARP].pdst)
            self.textBrowserRaw.clear()
            if packet.haslayer('Raw'):
                self.textBrowserRaw.append('Raw：%s' % packet[Raw].load.decode('utf-8', 'ignore'))
            if packet.haslayer('Padding'):
                self.textBrowserRaw.append('Padding：%s' % packet[Padding].load.decode('utf-8', 'ignore'))
        self.textBrowserDump.clear()
        f = open('hexdump.tmp', 'w')
        old = sys.stdout
        sys.stdout = f
        hexdump(packet)
        sys.stdout = old
        f.close()
        f = open('hexdump.tmp', 'r')
        content = f.read()
        self.textBrowserDump.append(content)
        f.close()
        os.remove('hexdump.tmp')
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = SnifferMainWindow()
    ui.setupUi(MainWindow)
    ui.setSlot()
    MainWindow.show()
    sys.exit(app.exec_())