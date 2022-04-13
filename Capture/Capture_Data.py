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
        self.count_text.textChanged.connect(self.count_change)
        self.listView.doubleClicked.connect(self.packet_select)

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

    def packet_select(self):
        row_index=self.listView.selectedIndexes()[0].row()
        packet=self.packets[row_index]
        box_selected=self.comboBox.currentText()
        raw_data=""
        decode_data=""
        if box_selected=="Ether":
            raw_data,decode_data=self.decode_ether(packet)
        self.raw_text.setText(raw_data)
        self.decode_text.setText(decode_data)

    def count_change(self):
        self.count = int(self.count_text.toPlainText())

    def set_sniffer(self, count=0, filter=""):
        self.sniffer = AsyncSniffer(count=count, filter=filter, prn=self.data_handle)

    def data_handle(self, packet):
        self.packets.append(packet)
        #self.decode_ether(packet)
        #self.decode_tcpip(packet)
        show_list = [i.summary() for i in self.packets]
        slm = QStringListModel()
        slm.setStringList(show_list)
        self.listView.setModel(slm)

    def capture(self):
        self.set_sniffer(int(self.count_text.toPlainText()), self.filter_text.toPlainText())
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()

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

    def decode_ether(self,packet):
        decode_data=""
        if packet.haslayer("Ether"):
            ether=packet.getlayer("Ether")
            raw_data=str(ether.raw_packet_cache)
            decode_data+=("目的地址:"+ether.fields["dst"])
            decode_data+=("   源地址:"+ether.fields["src"])
            decode_data+=("   类型:"+str(ether.fields["type"]))
            if str(ether.fields["type"])in self.type_dict:
                decode_data+=("\n类型解析为:"+str(self.type_dict[str(ether.fields["type"])]))
        else:
            return "无","无"
        return raw_data,decode_data
