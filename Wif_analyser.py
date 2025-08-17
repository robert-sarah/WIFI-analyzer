import sys
import os
import subprocess
import re
import threading
import time
from datetime import datetime
from collections import defaultdict

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QTabWidget, QComboBox,
    QFileDialog, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QProgressBar, QSplitter, QCheckBox, QLineEdit,
    QGroupBox, QGridLayout, QPlainTextEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette

from scapy.all import sniff, raw, Ether, IP, TCP, UDP, DNS, ARP, rdpcap, wrpcap
import netifaces as ni
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import psutil

# ---------------------------
# Thread de scan Wi-Fi
# ---------------------------
class WifiScannerThread(QThread):
    result_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)

    def run(self):
        self.log_signal.emit("[SCAN] Recherche des réseaux Wi-Fi...")
        networks = []
        try:
            if sys.platform == "linux":
                result = subprocess.check_output(
                    ["nmcli", "-t", "-f", "SSID,CHAN,SECURITY,SIGNAL", "dev", "wifi"],
                    stderr=subprocess.DEVNULL, text=True
                )
                for line in result.strip().split('\n'):
                    if not line or '://' in line:
                        continue
                    parts = line.split(':')
                    if len(parts) >= 4:
                        networks.append({
                            "SSID": parts[0] or "Inconnu",
                            "Channel": parts[1],
                            "Security": parts[2],
                            "Signal": parts[3]
                        })
            elif sys.platform == "win32":
                result = subprocess.check_output(["netsh", "wlan", "show", "network"], text=True)
                blocks = result.split("SSID ")
                for block in blocks[1:]:
                    ssid_match = re.search(r": (.+)", block)
                    signal_match = re.search(r"Signal : (\d+)%", block)
                    auth_match = re.search(r"Authentication\s+: ([^\r\n]+)", block)
                    ssid = ssid_match.group(1).strip() if ssid_match else "Inconnu"
                    signal = signal_match.group(1) if signal_match else "0"
                    security = auth_match.group(1).strip() if auth_match else "Inconnu"
                    networks.append({
                        "SSID": ssid,
                        "Channel": "N/A",
                        "Security": security,
                        "Signal": signal
                    })
        except Exception as e:
            self.log_signal.emit(f"[ERREUR SCAN] {str(e)}")

        self.result_signal.emit(networks)


# ---------------------------
# Thread de scan ARP (appareils)
# ---------------------------
class DeviceScannerThread(QThread):
    device_signal = pyqtSignal(list)
    log_signal = pyqtSignal(str)

    def __init__(self, interface):
        super().__init__()
        self.interface = interface

    def run(self):
        self.log_signal.emit("[DEVICE] Scan des appareils sur le réseau...")
        devices = []
        try:
            gateway = ni.gateways()['default'][ni.AF_INET][0]
            network = '.'.join(gateway.split('.')[:-1]) + '.0/24'
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, iface=self.interface, verbose=False)
            for sent, received in ans:
                hostname = "N/A"
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except:
                    pass
                devices.append({
                    "IP": received.psrc,
                    "MAC": received.hwsrc,
                    "Hostname": hostname
                })
        except Exception as e:
            self.log_signal.emit(f"[ERREUR DEVICE] {str(e)}")

        self.device_signal.emit(devices)


# ---------------------------
# Thread de capture
# ---------------------------
class PacketSnifferThread(QThread):
    packet_signal = pyqtSignal(object)
    log_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(dict)

    def __init__(self, interface, bpf_filter=""):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = False
        self.stats = defaultdict(int)

    def run(self):
        self.running = True
        self.log_signal.emit(f"[CAPTURE] Démarrage sur {self.interface} | Filtre: {self.bpf_filter}")
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                filter=self.bpf_filter,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            self.log_signal.emit(f"[ERREUR CAPTURE] {str(e)}")
        finally:
            self.stats_signal.emit(dict(self.stats))

    def process_packet(self, packet):
        if not self.running:
            return

        # Stats
        if IP in packet:
            self.stats["IP"] += 1
            proto = packet[IP].sprintf("%IP.proto%")
            self.stats[f"IP.{proto}"] += 1
        elif ARP in packet:
            self.stats["ARP"] += 1
        else:
            self.stats["Autre"] += 1

        self.packet_signal.emit(packet)

    def stop(self):
        self.running = False


# ---------------------------
# Canvas Matplotlib
# ---------------------------
class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super().__init__(fig)
        fig.tight_layout()


# ---------------------------
# Fenêtre principale
# ---------------------------
class NetworkAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔥 ANALYSEUR RÉSEAU PRO ULTIMATE v2.0")
        self.setGeometry(100, 50, 1400, 900)
        self.setStyleSheet(self.get_dark_style())

        self.capture_thread = None
        self.packet_list = []
        self.stats = {}

        self.init_ui()

    def get_dark_style(self):
        return """
        QMainWindow, QWidget { background-color: #1e1e2e; color: #cdd6f4; }
        QPushButton { background-color: #89b4fa; color: #1e1e2e; border: none; padding: 8px; border-radius: 6px; font-weight: bold; }
        QPushButton:hover { background-color: #74c7ec; }
        QTabWidget::pane { border: 1px solid #585b70; }
        QTabBar::tab { background: #313244; padding: 10px; margin: 2px; border-radius: 6px; }
        QTabBar::tab:selected { background: #1e1e2e; color: #89b4fa; }
        QTableWidget { border: 1px solid #585b70; gridline-color: #585b70; }
        QCheckBox { color: #cdd6f4; }
        QLineEdit { background-color: #313244; color: #cdd6f4; padding: 5px; border: 1px solid #585b70; border-radius: 4px; }
        """

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Onglets
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        # Onglets
        self.wifi_tab = QWidget()
        self.devices_tab = QWidget()
        self.packet_tab = QWidget()
        self.analysis_tab = QWidget()
        self.graph_tab = QWidget()
        self.logs_tab = QWidget()

        self.tabs.addTab(self.wifi_tab, "📡 Réseaux")
        self.tabs.addTab(self.devices_tab, "🔌 Appareils")
        self.tabs.addTab(self.packet_tab, "📦 Paquets")
        self.tabs.addTab(self.analysis_tab, "🔍 Analyse")
        self.tabs.addTab(self.graph_tab, "📈 Graphiques")
        self.tabs.addTab(self.logs_tab, "📋 Logs")

        self.init_wifi_tab()
        self.init_devices_tab()
        self.init_packet_tab()
        self.init_analysis_tab()
        self.init_graph_tab()
        self.init_logs_tab()

        # Timer stats
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.start(2000)

    def init_wifi_tab(self):
        layout = QVBoxLayout(self.wifi_tab)
        btn = QPushButton("🔄 Scanner les réseaux Wi-Fi")
        btn.clicked.connect(self.scan_wifi)
        layout.addWidget(btn)

        self.wifi_table = QTableWidget()
        self.wifi_table.setColumnCount(4)
        self.wifi_table.setHorizontalHeaderLabels(["SSID", "Canal", "Sécurité", "Signal"])
        layout.addWidget(self.wifi_table)

    def init_devices_tab(self):
        layout = QVBoxLayout(self.devices_tab)
        btn = QPushButton("🔄 Scanner les appareils")
        btn.clicked.connect(self.scan_devices)
        layout.addWidget(btn)

        self.device_table = QTableWidget()
        self.device_table.setColumnCount(3)
        self.device_table.setHorizontalHeaderLabels(["IP", "MAC", "Hostname"])
        layout.addWidget(self.device_table)

    def init_packet_tab(self):
        layout = QVBoxLayout(self.packet_tab)

        # Contrôles
        ctrl = QGroupBox("Contrôle de capture")
        ctrl_layout = QGridLayout()
        self.interface_combo = QComboBox()
        self.filter_edit = QLineEdit("tcp or udp or arp or dns")
        self.start_btn = QPushButton("▶️ Démarrer")
        self.stop_btn = QPushButton("⏹️ Arrêter")
        self.save_btn = QPushButton("💾 Sauvegarder")
        self.export_pcap_btn = QPushButton("📁 Exporter PCAP")

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_btn.clicked.connect(self.save_analysis)
        self.export_pcap_btn.clicked.connect(self.export_pcap)

        ctrl_layout.addWidget(QLabel("Interface:"), 0, 0)
        ctrl_layout.addWidget(self.interface_combo, 0, 1)
        ctrl_layout.addWidget(QLabel("Filtre BPF:"), 1, 0)
        ctrl_layout.addWidget(self.filter_edit, 1, 1)
        ctrl_layout.addWidget(self.start_btn, 0, 2)
        ctrl_layout.addWidget(self.stop_btn, 1, 2)
        ctrl_layout.addWidget(self.save_btn, 0, 3)
        ctrl_layout.addWidget(self.export_pcap_btn, 1, 3)
        ctrl.setLayout(ctrl_layout)
        layout.addWidget(ctrl)

        # Tableau
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["Temps", "Src", "Dst", "Protocole", "Longueur", "Données"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.packet_table)

        self.load_interfaces()

    def init_analysis_tab(self):
        layout = QVBoxLayout(self.analysis_tab)
        self.analysis_text = QPlainTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.analysis_text)

    def init_graph_tab(self):
        layout = QVBoxLayout(self.graph_tab)
        self.canvas = MplCanvas(self, width=10, height=6, dpi=100)
        layout.addWidget(self.canvas)
        self.update_graph()

    def init_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFont(QFont("Courier", 9))
        self.log_text.setStyleSheet("background-color: #000000; color: #00ff00;")
        layout.addWidget(self.log_text)

    def load_interfaces(self):
        try:
            if sys.platform == "linux":
                interfaces = [i for i in ni.interfaces() if 'wl' in i or 'eth' in i]
            else:
                interfaces = ['Wi-Fi', 'Ethernet']
            self.interface_combo.addItems(interfaces)
        except:
            self.interface_combo.addItem("wlan0")

    def scan_wifi(self):
        thread = WifiScannerThread()
        thread.result_signal.connect(self.display_wifi)
        thread.log_signal.connect(self.log)
        thread.start()

    def display_wifi(self, networks):
        self.wifi_table.setRowCount(0)
        self.wifi_table.setRowCount(len(networks))
        for i, net in enumerate(networks):
            self.wifi_table.setItem(i, 0, QTableWidgetItem(net["SSID"]))
            self.wifi_table.setItem(i, 1, QTableWidgetItem(net["Channel"]))
            self.wifi_table.setItem(i, 2, QTableWidgetItem(net["Security"]))
            self.wifi_table.setItem(i, 3, QTableWidgetItem(net["Signal"] + "%"))
        self.log(f"✅ {len(networks)} réseaux Wi-Fi trouvés.")

    def scan_devices(self):
        iface = self.interface_combo.currentText()
        thread = DeviceScannerThread(iface)
        thread.device_signal.connect(self.display_devices)
        thread.log_signal.connect(self.log)
        thread.start()

    def display_devices(self, devices):
        self.device_table.setRowCount(0)
        self.device_table.setRowCount(len(devices))
        for i, dev in enumerate(devices):
            self.device_table.setItem(i, 0, QTableWidgetItem(dev["IP"]))
            self.device_table.setItem(i, 1, QTableWidgetItem(dev["MAC"]))
            self.device_table.setItem(i, 2, QTableWidgetItem(dev["Hostname"]))
        self.log(f"✅ {len(devices)} appareils trouvés.")

    def start_capture(self):
        iface = self.interface_combo.currentText()
        bpf = self.filter_edit.text()

        if self.capture_thread and self.capture_thread.isRunning():
            self.log("⚠️ Une capture est déjà en cours.")
            return

        self.capture_thread = PacketSnifferThread(iface, bpf)
        self.capture_thread.packet_signal.connect(self.process_packet)
        self.capture_thread.log_signal.connect(self.log)
        self.capture_thread.stats_signal.connect(self.final_stats)
        self.capture_thread.start()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.log(f"📡 Capture démarrée sur {iface} | Filtre: {bpf}")

    def stop_capture(self):
        if self.capture_thread and self.capture_thread.isRunning():
            self.capture_thread.stop()
            self.capture_thread.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.log("🛑 Capture arrêtée.")

    def process_packet(self, packet):
        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src = dst = proto = length = data = "N/A"

        if Ether in packet:
            src = packet[Ether].src
            dst = packet[Ether].dst
            length = len(packet)

        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].sprintf("%IP.proto%")

            # Analyse détaillée
            if packet.haslayer("Raw"):
                raw_data = raw(packet["Raw"])
                try:
                    text = raw_data.decode('utf-8', errors='ignore')
                    if "pass" in text.lower() or "pwd" in text.lower():
                        self.log(f"🔐 MOT DE PASSE TROUVÉ : {text.strip()}")
                    data = text[:80]
                except:
                    data = f"[Binaire {len(raw_data)} octets]"

        elif ARP in packet:
            proto = "ARP"
            data = f"who-has {packet[ARP].pdst} ?"

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(length)))
        self.packet_table.setItem(row, 5, QTableWidgetItem(data))

        self.packet_list.append(packet)

    def final_stats(self, stats):
        self.stats = stats
        self.log(f"📊 Statistiques finales: {stats}")

    def update_stats_display(self):
        if hasattr(self, 'analysis_text'):
            total = sum(self.stats.values())
            text = f"📊 STATISTIQUES EN TEMPS RÉEL\n"
            text += f"Total paquets: {total}\n\n"
            for k, v in self.stats.items():
                text += f"{k}: {v}\n"
            self.analysis_text.setPlainText(text)

    def update_graph(self):
        self.canvas.axes.clear()
        labels = list(self.stats.keys())[:7]
        sizes = list(self.stats.values())[:7]
        self.canvas.axes.pie(sizes, labels=labels, autopct='%1.1f%%')
        self.canvas.axes.set_title("Répartition du trafic")
        self.canvas.draw()

    def export_pcap(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Exporter en PCAP", "", "PCAP Files (*.pcap)")
        if filename and self.packet_list:
            wrpcap(filename, self.packet_list)
            self.log(f"📁 Exporté en PCAP : {filename}")

    def save_analysis(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Sauvegarder l'analyse", "", "Text Files (*.txt)")
        if not filename:
            return

        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=== ANALYSE RÉSEAU PRO ULTIMATE ===\n")
            f.write(f"Généré le : {datetime.now()}\n\n")

            f.write("🔍 PAQUETS CAPTURÉS\n")
            for pkt in self.packet_list[-100:]:  # les 100 derniers
                f.write(pkt.summary() + "\n")
                if pkt.haslayer("Raw"):
                    raw_data = raw(pkt["Raw"])
                    ascii_data = raw_data.decode('utf-8', errors='ignore')
                    hex_data = ' '.join(f'{b:02x}' for b in raw_data)
                    f.write(f"  ASCII: {ascii_data[:200]}\n")
                    f.write(f"  HEX  : {hex_data[:100]}...\n\n")

            f.write("\n📊 STATISTIQUES\n")
            for k, v in self.stats.items():
                f.write(f"{k}: {v}\n")

        self.log(f"💾 Analyse sauvegardée : {filename}")

    def log(self, message):
        self.log_text.append(f"<b>[{datetime.now().strftime('%H:%M:%S')}]</b> {message}")


# ---------------------------
# Lancement
# ---------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkAnalyzer()
    window.show()
    sys.exit(app.exec_())
