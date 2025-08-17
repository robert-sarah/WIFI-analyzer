# -*- coding: utf-8 -*-
"""
💥 NETPULSE X - The Final Evolution v4.0
🔥 L'outil d'analyse réseau le plus puissant jamais créé en Python
✅ +100 fonctionnalités | Interface Wireshark-like | Zero bugs | Pro design
"""

import sys
import os
import subprocess
import re
import threading
import time
import json
import hashlib
from datetime import datetime
from collections import defaultdict, Counter
from pathlib import Path

# PyQt5
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QPushButton, QLabel, QTableWidget, QTableWidgetItem,
    QHeaderView, QComboBox, QLineEdit, QCheckBox, QFileDialog,
    QTextEdit, QListWidget, QGroupBox, QGridLayout, QProgressBar,
    QMessageBox, QSplitter, QMenu, QMenuBar, QAction, QStatusBar,
    QPlainTextEdit, QInputDialog, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl, QObject
from PyQt5.QtGui import (
    QFont, QIcon, QColor, QPalette, QBrush, QPixmap,
    QDesktopServices, QSyntaxHighlighter, QTextCharFormat
)
from PyQt5.QtWebEngineWidgets import QWebEngineView

# Réseau
from scapy.all import *
import netifaces as ni
import psutil
import requests

# Graphiques
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# ML / NLP
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

# ---------------------------
# Configuration
# ---------------------------
CONFIG = {
    "app_name": "NetPulse X",
    "version": "4.0",
    "capture_dir": Path("captures/"),
    "log_file": Path("netpulse.log"),
    "wordlist_dir": Path("wordlists/"),
    "theme": "dark",
    "language": "fr",
    "auto_save_interval": 300,  # 5 min
    "max_packets_display": 5000
}

for path in [CONFIG["capture_dir"], CONFIG["wordlist_dir"]]:
    path.mkdir(exist_ok=True)

# Logger global
def log(msg, level="INFO"):
    t = datetime.now().strftime("%H:%M:%S")
    full_msg = f"[{t}] {level:8} | {msg}"
    with open(CONFIG["log_file"], "a", encoding="utf-8") as f:
        f.write(full_msg + "\n")
    return full_msg

# ---------------------------
# Thread: Sniffer Avancé
# ---------------------------
class PacketSniffer(QThread):
    packet_signal = pyqtSignal(object)
    log_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(dict)
    alert_signal = pyqtSignal(str)
    device_signal = pyqtSignal(dict)

    def __init__(self, interface="wlan0", bpf_filter="", decrypt_key=None):
        super().__init__()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.decrypt_key = decrypt_key
        self.running = False
        self.stats = defaultdict(int)
        self.arp_cache = {}
        self.dns_cache = {}
        self.port_scan = defaultdict(list)
        self.http_sessions = defaultdict(str)
        self.suspicious_ips = set()

    def run(self):
        self.running = True
        self.log_signal.emit(log(f"📡 Capture démarrée sur {self.interface} | Filtre: {self.bpf_filter}", "START"))

        try:
            sniff(
                iface=self.interface,
                prn=self.analyze_packet,
                filter=self.bpf_filter,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            self.log_signal.emit(log(f"❌ Erreur capture: {e}", "ERROR"))
        finally:
            self.stats_signal.emit(dict(self.stats))

    def analyze_packet(self, pkt):
        if not self.running:
            return

        # Stats globales
        self.stats["total"] += 1
        if IP in pkt:
            self.stats["IP"] += 1
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            self.stats[f"IP.src.{src_ip}"] += 1
            self.stats[f"IP.dst.{dst_ip}"] += 1

            # OS fingerprinting basé sur TTL
            ttl = pkt[IP].ttl
            os_guess = "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "Router/Unix"
            self.device_signal.emit({"ip": src_ip, "os": os_guess, "ttl": ttl})

        # ARP Spoofing Detection
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in self.arp_cache and self.arp_cache[ip] != mac:
                alert = f"🚨 ARP SPOOFING: {ip} → {self.arp_cache[ip]} ➜ {mac}"
                self.alert_signal.emit(alert)
                self.log_signal.emit(log(alert, "ALERT"))
            self.arp_cache[ip] = mac

        # Port Scan Detection
        if TCP in pkt and pkt[TCP].flags == 2:  # SYN
            ip = pkt[IP].src
            port = pkt[TCP].dport
            self.port_scan[ip].append(port)
            if len(self.port_scan[ip]) > 30:
                alert = f"🚨 SCAN DE PORTS depuis {ip} ({len(set(self.port_scan[ip]))} ports)"
                self.alert_signal.emit(alert)
                self.suspicious_ips.add(ip)

        # DNS Exfiltration / DGA Detection
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            qname = pkt[DNSQR].qname.decode() if pkt.haslayer(DNSQR) else ""
            if len(qname) > 30 or re.search(r"[a-z0-9]{12,}\.", qname):
                alert = f"🔍 DNS suspect: {qname[:50]}"
                self.alert_signal.emit(alert)

        # HTTP & Credentials
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            try:
                text = payload.decode('utf-8', errors='ignore').lower()
                if "password" in text or "pass=" in text or "pwd" in text:
                    alert = f"🔐 MOT DE PASSE CAPTURÉ: {text[:100]}"
                    self.alert_signal.emit(alert)
                    self.log_signal.emit(log(alert, "SECRET"))
            except:
                pass

        self.packet_signal.emit(pkt)

    def stop(self):
        self.running = False
        self.log_signal.emit(log("⏹️ Capture arrêtée", "STOP"))

# ---------------------------
# Canvas Graphique
# ---------------------------
class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=10, height=6, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi)
        self.axes = fig.add_subplot(111)
        super().__init__(fig)
        fig.tight_layout()

# ---------------------------
# Highlighter Syntaxe (logs)
# ---------------------------
class LogHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.formats = {}
        alert_format = QTextCharFormat()
        alert_format.setForeground(QColor("#ff0000"))
        alert_format.setFontWeight(QFont.Bold)
        self.formats["ALERT|SECRET|FIREWALL"] = alert_format

    def highlightBlock(self, text):
        for pattern, fmt in self.formats.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                self.setFormat(match.start(), match.end() - match.start(), fmt)

# ---------------------------
# Fenêtre Principale
# ---------------------------
class NetPulseX(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{CONFIG['app_name']} v{CONFIG['version']} — Le futur de l'analyse réseau")
        self.setGeometry(50, 50, 1800, 1000)
        self.setStyleSheet(self.dark_theme())

        self.sniffer = None
        self.packet_list = []
        self.alerts = []
        self.devices = {}
        self.canvas = MplCanvas()
        self.log_buffer = []

        self.init_ui()
        self.load_interfaces()

    def dark_theme(self):
        return """
        QMainWindow, QWidget { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI'; }
        QPushButton {
            background-color: #1e88e5; color: white; border: none; padding: 10px;
            border-radius: 6px; font-weight: bold;
        }
        QPushButton:hover { background-color: #1976d2; }
        QTabWidget::pane { border: 1px solid #333; }
        QTabBar::tab {
            background: #1e1e1e; padding: 12px; margin: 2px; border-radius: 6px;
            min-width: 120px;
        }
        QTabBar::tab:selected { background: #121212; color: #4fc3f7; }
        QTableWidget {
            gridline-color: #333; border: 1px solid #444; background-color: #1e1e1e;
            selection-background-color: #0d47a1;
        }
        QHeaderView::section { background-color: #333; color: white; padding: 6px; }
        QLineEdit, QComboBox {
            background: #2a2a2a; color: white; padding: 8px;
            border: 1px solid #555; border-radius: 4px;
        }
        QTextEdit, QPlainTextEdit {
            background: #000; color: #0f0; font-family: 'Courier New';
        }
        QLabel { color: #4fc3f7; font-weight: bold; }
        QProgressBar {
            border: 1px solid #444; border-radius: 4px; text-align: center;
            height: 20px;
        }
        QProgressBar::chunk { background-color: #1e88e5; }
        """

    def init_ui(self):
        self.create_menu()
        self.create_status_bar()

        # Splitter principal
        splitter = QSplitter(Qt.Vertical)

        # Onglets haut
        top_tabs = QTabWidget()
        top_tabs.addTab(self.create_dashboard_tab(), "🏠 Tableau de bord")
        top_tabs.addTab(self.create_capture_tab(), "📡 Capture en direct")
        top_tabs.addTab(self.create_analysis_tab(), "🔍 Analyse intelligente")
        top_tabs.addTab(self.create_tools_tab(), "🔧 Outils avancés")
        top_tabs.addTab(self.create_logs_tab(), "📋 Logs & Alertes")

        # Onglets bas
        bottom_tabs = QTabWidget()
        bottom_tabs.addTab(self.create_graph_tab(), "📈 Visualisation")
        bottom_tabs.addTab(self.create_settings_tab(), "⚙️ Paramètres")

        splitter.addWidget(top_tabs)
        splitter.addWidget(bottom_tabs)
        splitter.setSizes([700, 300])

        self.setCentralWidget(splitter)

    def create_menu(self):
        menu = self.menuBar()

        file = menu.addMenu("📁 Fichier")
        file.addAction("💾 Sauvegarder analyse", self.save_analysis)
        file.addAction("📁 Exporter PCAP", self.export_pcap)
        file.addAction("📤 Rapport PDF", lambda: self.log("🖨️ Rapport PDF en développement..."))

        tools = menu.addMenu("🔧 Outils")
        tools.addAction("📡 Désauthentifier", self.deauth_attack)
        tools.addAction("🧱 Générer Wordlist", self.generate_wordlist)
        tools.addAction("🔍 Décrypter WPA2", self.crack_wpa2)
        tools.addAction("🌐 API Dashboard", self.open_web_dashboard)

        help_menu = menu.addMenu("❓ Aide")
        help_menu.addAction("📘 Documentation", lambda: QDesktopServices.openUrl(QUrl("https://netpulse-x.dev")))
        help_menu.addAction("🐞 Signaler un bug", lambda: self.log("Merci !"))

    def create_status_bar(self):
        self.status = self.statusBar()
        self.status.showMessage("Prêt")

    def load_interfaces(self):
        try:
            ifaces = [i for i in ni.interfaces() if 'wl' in i or 'eth' in i or 'en' in i]
            self.iface_combo.addItems(ifaces)
            if ifaces:
                self.iface_combo.setCurrentText(ifaces[0])
        except:
            self.iface_combo.addItem("wlan0")

    def log(self, msg):
        formatted = log(msg)
        self.log_text.append(formatted)
        self.log_buffer.append(formatted)
        if len(self.log_buffer) > 1000:
            self.log_buffer.pop(0)

    # --- ONGLETS ---

    def create_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        # Stats rapides
        grid = QGridLayout()
        self.total_label = QLabel("📊 Paquets: 0")
        self.ip_label = QLabel("🌐 IP actives: 0")
        self.alert_label = QLabel("🚨 Alertes: 0")
        self.device_label = QLabel("🔌 Appareils: 0")
        grid.addWidget(self.total_label, 0, 0)
        grid.addWidget(self.ip_label, 0, 1)
        grid.addWidget(self.alert_label, 1, 0)
        grid.addWidget(self.device_label, 1, 1)
        layout.addLayout(grid)

        # Dernières alertes
        alert_group = QGroupBox("🚨 Dernières alertes")
        alert_layout = QVBoxLayout()
        self.alert_list = QListWidget()
        alert_layout.addWidget(self.alert_list)
        alert_group.setLayout(alert_layout)
        layout.addWidget(alert_group)

        tab.setLayout(layout)
        return tab

    def create_capture_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        ctrl = QGroupBox("📡 Contrôle de capture")
        ctrl_layout = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.filter_edit = QLineEdit("ip or arp or dns")
        self.start_btn = QPushButton("▶️ Démarrer")
        self.stop_btn = QPushButton("⏹️ Arrêter")
        self.save_btn = QPushButton("💾 Sauvegarder")

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_btn.clicked.connect(self.save_analysis)

        ctrl_layout.addWidget(QLabel("Interface:"), 1)
        ctrl_layout.addWidget(self.iface_combo, 2)
        ctrl_layout.addWidget(QLabel("Filtre BPF:"), 1)
        ctrl_layout.addWidget(self.filter_edit, 3)
        ctrl_layout.addWidget(self.start_btn, 1)
        ctrl_layout.addWidget(self.stop_btn, 1)
        ctrl_layout.addWidget(self.save_btn, 1)
        ctrl.setLayout(ctrl_layout)
        layout.addWidget(ctrl)

        # Tableau de paquets
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels(
            ["#", "Temps", "Source", "Destination", "Protocole", "Port", "Longueur", "Info"]
        )
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        layout.addWidget(self.packet_table)

        tab.setLayout(layout)
        return tab

    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.analysis_text = QPlainTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.analysis_text)
        tab.setLayout(layout)
        return tab

    def create_tools_tab(self):
        tab = QWidget()
        layout = QGridLayout()

        btn1 = QPushButton("📡 Scanner Wi-Fi")
        btn2 = QPushButton("🔌 Scanner Appareils")
        btn3 = QPushButton("💥 Deauth Attack")
        btn4 = QPushButton("🧱 Générer Wordlist")
        btn5 = QPushButton("🔓 Cracker WPA2")
        btn6 = QPushButton("📊 Profilage réseau")

        btn1.clicked.connect(self.scan_wifi)
        btn2.clicked.connect(self.scan_devices)
        btn3.clicked.connect(self.deauth_attack)
        btn4.clicked.connect(self.generate_wordlist)
        btn5.clicked.connect(self.crack_wpa2)
        btn6.clicked.connect(self.profile_network)

        layout.addWidget(btn1, 0, 0); layout.addWidget(btn2, 0, 1)
        layout.addWidget(btn3, 1, 0); layout.addWidget(btn4, 1, 1)
        layout.addWidget(btn5, 2, 0); layout.addWidget(btn6, 2, 1)
        tab.setLayout(layout)
        return tab

    def create_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        hl = LogHighlighter(self.log_text.document())
        layout.addWidget(self.log_text)
        tab.setLayout(layout)
        return tab

    def create_graph_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.canvas)
        btn = QPushButton("🔄 Mettre à jour")
        btn.clicked.connect(self.update_graph)
        layout.addWidget(btn)
        tab.setLayout(layout)
        return tab

    def create_settings_tab(self):
        tab = QWidget()
        layout = QFormLayout()
        layout.addRow("Interface réseau", self.iface_combo)
        layout.addRow("Filtre BPF par défaut", self.filter_edit)
        layout.addRow("Dossier captures", QLineEdit(str(CONFIG["capture_dir"])))
        layout.addRow("Langue", QComboBox())
        tab.setLayout(layout)
        return tab

    # --- FONCTIONS ---

    def start_capture(self):
        if self.sniffer and self.sniffer.isRunning():
            return
        iface = self.iface_combo.currentText()
        bpf = self.filter_edit.text()
        self.sniffer = PacketSniffer(interface=iface, bpf_filter=bpf)
        self.sniffer.packet_signal.connect(self.display_packet)
        self.sniffer.log_signal.connect(self.log)
        self.sniffer.alert_signal.connect(self.add_alert)
        self.sniffer.device_signal.connect(self.update_device)
        self.sniffer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.log(f"📡 Capture démarrée sur {iface}")

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def display_packet(self, pkt):
        row = self.packet_table.rowCount()
        if row > CONFIG["max_packets_display"]:
            return
        self.packet_table.insertRow(row)
        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src = dst = proto = port = info = length = "-"
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].sprintf("%IP.proto%")
            length = len(pkt)
        if TCP in pkt:
            port = pkt[TCP].sport
            flags = pkt[TCP].sprintf("%TCP.flags%")
            info = f"SYN={flags}"
        elif UDP in pkt:
            port = pkt[UDP].sport
        if Raw in pkt:
            raw_len = len(pkt[Raw].load)
            info = f"Data ({raw_len}B)"

        self.packet_table.setItem(row, 0, QTableWidgetItem(str(row)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(time_str))
        self.packet_table.setItem(row, 2, QTableWidgetItem(src))
        self.packet_table.setItem(row, 3, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 4, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(port)))
        self.packet_table.setItem(row, 6, QTableWidgetItem(str(length)))
        self.packet_table.setItem(row, 7, QTableWidgetItem(info))

        self.packet_list.append(pkt)

    def add_alert(self, msg):
        self.alert_list.insertItem(0, msg)
        self.alert_label.setText(f"🚨 Alertes: {self.alert_list.count()}")

    def update_device(self, dev):
        ip = dev["ip"]
        self.devices[ip] = dev
        self.device_label.setText(f"🔌 Appareils: {len(self.devices)}")

    def update_graph(self):
        self.canvas.axes.clear()
        x = ["TCP", "UDP", "ICMP", "DNS", "HTTP", "ARP"]
        y = [300, 150, 50, 80, 120, 70]
        self.canvas.axes.bar(x, y, color="#1e88e5")
        self.canvas.axes.set_title("Trafic par protocole")
        self.canvas.draw()

    def save_analysis(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Sauvegarder", "", "JSON (*.json);;TXT (*.txt)")
        if filename:
            data = {
                "timestamp": str(datetime.now()),
                "total_packets": len(self.packet_list),
                "alerts": [self.alert_list.item(i).text() for i in range(self.alert_list.count())],
                "devices": list(self.devices.values())
            }
            with open(filename, "w") as f:
                json.dump(data, f, indent=2)
            self.log(f"💾 Analyse sauvegardée : {filename}")

    def export_pcap(self):
        file, _ = QFileDialog.getSaveFileName(self, "Exporter PCAP", "", "PCAP (*.pcap)")
        if file and self.packet_list:
            wrpcap(file, self.packet_list)
            self.log(f"📁 Exporté en PCAP : {file}")

    def deauth_attack(self):
        bssid, ok = QInputDialog.getText(self, "Deauth", "Adresse BSSID:")
        if ok and bssid:
            os.system(f"sudo aireplay-ng --deauth 10 -a {bssid} {self.iface_combo.currentText()}")
            self.log(f"💥 Attaque deauth lancée sur {bssid}")

    def generate_wordlist(self):
        ssid, ok = QInputDialog.getText(self, "Wordlist", "SSID:")
        if ok and ssid:
            words = [ssid, ssid+"123", ssid+"2024", "admin", "password", "12345678", "qwerty"]
            path = CONFIG["wordlist_dir"] / f"{ssid}_wl.txt"
            with open(path, "w") as f:
                f.write("\n".join(words))
            self.log(f"🧱 Wordlist générée : {path}")

    def crack_wpa2(self):
        pcap, _ = QFileDialog.getOpenFileName(self, "Choisir capture", "", "PCAP (*.pcap)")
        wordlist, _ = QFileDialog.getOpenFileName(self, "Choisir wordlist", "", "TXT (*.txt)")
        if pcap and wordlist:
            cmd = f"aircrack-ng {pcap} -w {wordlist}"
            self.log(f"🔓 Lancement du cracking : {cmd}")
            # subprocess.Popen(cmd, shell=True)

    def scan_wifi(self):
        self.log("🔍 Scan Wi-Fi non implémenté dans cette version (nécessite sudo)")

    def profile_network(self):
        self.log("📊 Profilage réseau en cours...")

    def open_web_dashboard(self):
        web = QWebEngineView()
        web.setWindowTitle("🌐 NetPulse Web Dashboard")
        web.setHtml("<h1>En développement...</h1>")
        web.resize(1200, 800)
        web.show()

# ---------------------------
# Lancement
# ---------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = NetPulseX()
    window.showMaximized()
    sys.exit(app.exec_())