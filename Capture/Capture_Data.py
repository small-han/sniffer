from scapy.all import *
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QHBoxLayout
import threading


class MainWidget(QWidget):

    def __init__(self):
        super(MainWidget, self).__init__()
        self.resize(1000, 500)
        self.sniffer = None

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

    def set_sniffer(self, count, filter):
        self.sniffer = AsyncSniffer(count=count, filter=filter, prn=self.data_handle)

    def data_handle(self, packet):
        print(packet.summary())

    def capture(self):
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()
