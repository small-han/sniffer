from scapy.all import *
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton


class MainWidget(QWidget):

    def __init__(self):
        super(MainWidget, self).__init__()
        self.sniffer = None

    def set_sniffer(self, count, filter):
        self.sniffer = AsyncSniffer(count=count, filter=filter, prn=self.data_handle)

    def data_handle(self, packet):
        print(packet.summary())

    def Capture(self):
        self.sniffer.start()

    def Stop(self):
        self.sniffer.stop()
