from scapy.all import *
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QHBoxLayout
from designer.designer import Ui_Form
from PyQt5.QtCore import QStringListModel, QThread


class MainWidget(QWidget, Ui_Form):

    def __init__(self):
        super(MainWidget, self).__init__()
        self.setupUi(self)
        self.sniffer = None
        self.packets = []

        self.start_button.pressed.connect(self.capture)
        self.stop_button.pressed.connect(self.stop)
        self.count_text.textChanged.connect(self.count_change)

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

    def count_change(self):
        self.count = int(self.count_text.toPlainText())

    def set_sniffer(self, count=0, filter=""):
        self.sniffer = AsyncSniffer(count=count, filter=filter, prn=self.data_handle)

    def data_handle(self, packet):
        self.packets.append(packet)
        self.decode_tcpip(packet)
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
                print("hello")
