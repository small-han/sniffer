from Capture.Capture_Data import MainWidget
from QtShow.QtShow import QtShow
from PyQt5.QtWidgets import QApplication
import time
import sys

if __name__ == '__main__':
    app = QApplication(sys.argv)
    my_widget = MainWidget()
    my_widget.show()
    sys.exit(app.exec())
