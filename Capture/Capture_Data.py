from scapy.all import *
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QHBoxLayout
from designer.designer import Ui_Form
from PyQt5.QtCore import QStringListModel, QThread
import json


class MainWidget(QWidget, Ui_Form):

    def __init__(self):
        super(MainWidget, self).__init__()
        self.setupUi(self)
        self.sniffer = None
        self.packets = []

        self.port_dict = {}
        with open("./PORT.json", "r") as f:
            self.port_dict = json.load(f)
        with open("./TYPE.json", "r") as f:
            self.type_dict = json.load(f)

        self.start_button.pressed.connect(self.capture)
        self.stop_button.pressed.connect(self.stop)
        self.clearButton.pressed.connect(self.clear)
        self.listView.clicked.connect(self.packet_select)
        self.comboBox.activated.connect(self.show_data)

    """
        self.start_button = QPushButton("开始嗅探", self)
        self.stop_button = QPushButton("停止嗅探", self)
        self.button_layout = QHBoxLayout()
        self.init_button()

        self.setLayout(self.button_layout)
    def init_button(self):
        self.button_layout.addWidget(self.start_button)
        self.button_layout.addWidget(self.stop_button)
        self.start_button.pressed.connect(self.capture)
        self.stop_button.pressed.connect(self.stop)
    """

    def clear(self):
        self.packets = []
        show_list = [i.summary() for i in self.packets]
        slm = QStringListModel()
        slm.setStringList(show_list)
        self.listView.setModel(slm)
        self.raw_text.clear()
        self.decode_text.clear()

    def show_data(self):
        raw_data = str(self.packet.original)
        decode_data = ""
        raw_data = ""
        box_selected = self.comboBox.currentText()
        if box_selected == "all":
            for i in self.layers_list:
                raw_data += str(i.raw_packet_cache)
                decode_data += i.name
                decode_data += "\n"
                for key, value in i.fields.items():
                    decode_data += ("   " + str(key) + ":" + str(value))
                decode_data += "\n"
        else:
            for i in self.layers_list:
                if i.name == box_selected:
                    if i.name == "IP":
                        raw_data, decode_data = self.decode_ip()
                    elif i.name == "Ethernet":
                        raw_data, decode_data = self.decode_ether()
                    elif i.name == "TCP":
                        raw_data, decode_data = self.decode_tcp()
                    elif i.name == "UDP":
                        raw_data, decode_data = self.decode_udp()
                    else:
                        raw_data = str(i.raw_packet_cache)
                        decode_data += i.name
                        decode_data += "\n"
                        for key, value in i.fields.items():
                            decode_data += ("   " + str(key) + ":" + str(value))
                        decode_data += "\n"
                else:
                    continue
        self.raw_text.setText(raw_data)
        self.decode_text.setText(decode_data)

    def packet_select(self):
        row_index = self.listView.selectedIndexes()[0].row()
        self.packet = self.packets[row_index]

        self.comboBox.clear()
        self.get_packet_layers()
        layer_name = [i.name for i in self.layers_list]
        self.comboBox.addItem("all")
        self.comboBox.addItems(layer_name)
        self.show_data()
        """
        box_selected = self.comboBox.currenVtText()
        raw_data = ""
        decode_data = ""
        if box_selected == "Ether":
            raw_data, decode_data = self.decode_ether(packet)
        elif box_selected == "IP":
            raw_data, decode_data = self.decode_ip(packet)
        elif box_selected == "all":
            raw_data, decode_data = self.decode_all(packet)
        self.raw_text.setText(raw_data)
        self.decode_text.setText(decode_data)
        """

    def set_sniffer(self, count=0, filter=""):
        self.sniffer = AsyncSniffer(count=count, filter=filter, prn=self.data_handle)

    def data_handle(self, packet):
        self.packets.append(packet)
        # self.decode_ether(packet)
        # self.decode_tcpip(packet)
        show_list = [i.summary() for i in self.packets]
        slm = QStringListModel()
        slm.setStringList(show_list)
        self.listView.setModel(slm)

    def capture(self):
        self.set_sniffer(int(self.count_text.toPlainText()), self.filter_text.toPlainText())
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()

    def get_packet_layers(self):
        self.layers_list = []
        t = 0
        while True:
            layer = self.packet.getlayer(t)
            if layer is None:
                break
            self.layers_list.append(layer)
            t += 1

    def decode_all(self, packet):
        layers_list = []
        decode_data = ""
        raw_data = str(packet.original)
        t = 0
        while True:
            layer = packet.getlayer(t)
            if layer is None:
                break
            layers_list.append(layer)
            t += 1
        for i in layers_list:
            decode_data += i.name
            decode_data += "\n"
            for key, value in i.fields.items():
                decode_data += ("   " + str(key) + ":" + str(value))
            decode_data += "\n"
        return raw_data, decode_data

    def decode_tcpip(self, packet):
        data = {}
        if packet.haslayer("IP"):
            if packet.haslayer("TCP"):
                ip = packet.getlayer("IP")
                tcp = packet.getlayer("TCP")
                data["src"] = ip.src + ":" + str(ip.sport)
                data["dst"] = ip.dst + ":" + str(ip.dport)
                if tcp.dport in self.port_dict:
                    data['Procotol'] = self.port_dict[tcp.dport]
                elif tcp.sport in self.port_dict:
                    data['Procotol'] = self.port_dict[tcp.sport]
                else:
                    data['Procotol'] = "TCP"

    def decode_ip(self):
        decode_data = ""
        if self.packet.haslayer("IP"):
            ip = self.packet.getlayer("IP")
            decode_data += ("版本:" + str(ip.fields["version"]))
            decode_data += ("   首部长度:" + str(ip.fields["ihl"]))
            decode_data += ("   区分服务:" + str(ip.fields["tos"]))
            decode_data += ("   总长度:" + str(ip.fields["len"]))
            decode_data += ("   标识:" + str(ip.fields["id"]))
            decode_data += ("   片偏移:" + str(ip.fields["frag"]))
            decode_data += ("\n生存时间:" + str(ip.fields["ttl"]))
            decode_data += ("   协议:" + str(ip.fields["proto"]))
            decode_data += ("   首部校验和:" + str(ip.fields["chksum"]))
            decode_data += ("\n源地址:" + ip.fields["src"])
            decode_data += ("   目的地址:" + ip.fields["dst"])
            raw_data = str(ip.raw_packet_cache)
            if str(ip.fields["proto"]) in self.port_dict:
                decode_data += ("\n类型解析为:" + str(self.port_dict[str(ip.fields["proto"])]))
        else:
            return "ip:无", "ip:无"
        return raw_data, decode_data

    def decode_ether(self):
        decode_data = ""
        if self.packet.haslayer("Ether"):
            ether = self.packet.getlayer("Ether")
            raw_data = str(ether.raw_packet_cache)
            decode_data += ("目的地址:" + ether.fields["dst"])
            decode_data += ("   源地址:" + ether.fields["src"])
            decode_data += ("   类型:" + str(ether.fields["type"]))
            if str(ether.fields["type"]) in self.type_dict:
                decode_data += ("\n类型解析为:" + str(self.type_dict[str(ether.fields["type"])]))
        else:
            return "ether:无", "ether:无"
        return raw_data, decode_data

    def decode_tcp(self):
        decode_data = ""
        if self.packet.haslayer("TCP"):
            tcp = self.packet.getlayer("TCP")
            decode_data += ("源端口:" + str(tcp.fields["sport"]))
            decode_data += ("   目的端口:" + str(tcp.fields["dport"]))
            decode_data += ("   序号:" + str(tcp.fields["seq"]))
            decode_data += ("   确认号:" + str(tcp.fields["ack"]))
            decode_data += ("   数据偏移:" + str(tcp.fields["dataofs"]))
            decode_data += ("   保留:" + str(tcp.fields["reserved"]))
            decode_data += ("   窗口:" + str(tcp.fields["window"]))
            decode_data += ("   检验和:" + str(tcp.fields["chksum"]))
            decode_data += ("   紧急指针:" + str(tcp.fields["urgptr"]))
            raw_data = str(tcp.raw_packet_cache)
        return raw_data, decode_data

    def decode_udp(self):
        decode_data = ""
        if self.packet.haslayer("UDP"):
            udp = self.packet.getlayer("UDP")
            decode_data += ("源端口:" + str(udp.fields["sport"]))
            decode_data += ("   目的端口:" + str(udp.fields["dport"]))
            decode_data += ("   长度:" + str(udp.fields["len"]))
            decode_data += ("   校验和:" + str(udp.fields["chksum"]))
            raw_data = str(udp.raw_packet_cache)
        return raw_data, decode_data
