from Capture.Capture_Data import CaptureData
import time


if __name__ == '__main__':
    my_capturedata=CaptureData(count=10,filter="")
    my_capturedata.Capture()
    time.sleep(1)
    my_capturedata.Stop()

