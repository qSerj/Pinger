import sys
import subprocess
from PyQt5.QtWidgets import QApplication, QSystemTrayIcon, QMenu
from PyQt5.QtGui import QIcon, QPixmap, QColor
from PyQt5.QtCore import QTimer

HOST = "8.8.8.8"  # Ресурс для проверки

def create_color_icon(color_name):
    pixmap = QPixmap(16, 16)
    pixmap.fill(QColor(color_name))
    return QIcon(pixmap)

def check_ping():
    # -c 1 (1 пакет), -W 1 (таймаут 1 сек)
    res = subprocess.call(["ping", "-c", "1", "-W", "1", HOST], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if res == 0:
        tray.setIcon(create_color_icon("green"))
        tray.setToolTip(f"{HOST}: Доступен")
    else:
        tray.setIcon(create_color_icon("red"))
        tray.setToolTip(f"{HOST}: НЕДОСТУПЕН")

app = QApplication(sys.argv)
app.setQuitOnLastWindowClosed(False)

tray = QSystemTrayIcon()
tray.setIcon(create_color_icon("gray"))
tray.setVisible(True)

# Таймер проверки каждые 5 секунд
timer = QTimer()
timer.timeout.connect(check_ping)
timer.start(5000)

check_ping()
sys.exit(app.exec_())