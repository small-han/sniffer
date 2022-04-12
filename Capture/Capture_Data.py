from scapy.all import *


class CaptureData(object):

    def __init__(self, count, filter):
        self.sniffer = AsyncSniffer(count=count, filter=filter,prn=self.data_handle)

    def data_handle(self, packet):
        print(packet.summary())

    def Capture(self):
        self.sniffer.start()

    def Stop(self):
        self.sniffer.stop()
