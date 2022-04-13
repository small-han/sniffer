from Capture.Capture_Data import MainWidget
from PyQt5.QtWidgets import QApplication
import time
import sys

if __name__ == '__main__':
    app = QApplication(sys.argv)
    my_widget = MainWidget()
    my_widget.set_sniffer(0,"")
    my_widget.show()
    app.exec()
