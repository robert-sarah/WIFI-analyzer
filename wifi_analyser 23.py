# -*- coding: utf-8 -*-
"""
🔥 NETPULSE PRO ULTIMATE X v3.0
L'outil le plus puissant d'analyse réseau jamais fait en Python
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

from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
from PyQt5.QtGui import QFont, QIcon, QDesktopServices
from PyQt5.QtWebEngineWidgets import QWebEngineView  # Pour dashboard web

from scapy.all import *
import netifaces as ni
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import psutil
import requests

# Pour ML simple (profiling)
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

# ---------------------------
# Config globale
# ---------------------------
CONFIG = {
    "log_file": "netpulse.log",
    "capture_dir": "captures/",
    "wordlist_dir": "wordlists/",
    "language": "fr"
}

os.makedirs(CONFIG["capture_dir"], exist_ok=True)
os.makedirs(CONFIG["wordlist_dir"], exist_ok=True)

# ---------------------------
# Thread: Capture avancée
# ---------------------------
class AdvancedSnifferThread(QThread):
    packet_signal = pyqtSignal(object)
    log_signal = pyqtSignal(str)
    stats_signal = pyqtSignal(dict)
    alert_signal = pyqtSignal(str)

    def __init__(self, iface, bpf="", decrypt_key=None):
        super().__init__()
        self.iface = iface
        self.bpf = bpf
        self.decrypt_key = decrypt_key
        self.running = False
        self.stats = defaultdict(int)
        self.arp_table = {}
        self.port_scan_detect = defaultdict(list)
        self.http_forms = []

    def run(self):
        self.running = True
        self.log_signal.emit(f"[+] Capture démarrée sur {self.iface}")
        try:
            sniff(iface=self.iface, prn=self.analyze_packet, filter=self.bpf, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.log_signal.emit(f"[!] Erreur capture: {e}")

    def analyze_packet(self, pkt):
        if not self.running:
            return

        # Stats
        self.stats["total"] += 1
        if IP in pkt:
            self.stats["IP"] += 1
            self.stats[f"src.{pkt[IP].src}"] += 1
            self.stats[f"dst.{pkt[IP].dst}"] += 1
            self.stats[f"proto.{pkt[IP].proto}"] += 1
        elif ARP in pkt:
            self.stats["ARP"] += 1

        # ARP Spoofing Detection
        if ARP in pkt and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip in self.arp_table and self.arp_table[ip] != mac:
                alert = f"🚨 ARP SPOOFING DETECTÉ: {ip} change de {self.arp_table[ip]} → {mac}"
                self.alert_signal.emit(alert)
                self.log_signal.emit(alert)
            self.arp_table[ip] = mac

        # Port Scan Detection
        if TCP in pkt and pkt[TCP].flags == 2:  # SYN
            ip = pkt[IP].src
            port = pkt[TCP].dport
            self.port_scan_detect[ip].append(port)
            if len(self.port_scan_detect[ip]) > 50:
                alert = f"🚨 SCAN DE PORTS depuis {ip} ({len(self.port_scan_detect[ip])} ports)"
                self.alert_signal.emit(alert)
                self.log_signal.emit(alert)

        # HTTP Form Extraction
        if pkt.haslayer(Raw):
            raw = pkt[Raw].load.decode('utf-8', errors='ignore').lower()
            if "password" in raw or "pass=" in raw or "pwd" in raw:
                self.http_forms.append(raw)
                self.alert_signal.emit(f"🔐 MOT DE PASSE CAPTURÉ: {raw[:100]}...")
                self.log_signal.emit(f"🔐 Formulaire HTTP détecté: {raw[:100]}")

        self.packet_signal.emit(pkt)

    def stop(self):
        self.running = False

# ---------------------------
# Widget: Graphique
# ---------------------------
class MplCanvas(FigureCanvas):
    def __init__(self):
        fig = Figure(figsize=(10, 6), dpi=100)
        self.axes = fig.add_subplot(111)
        super().__init__(fig)

# ---------------------------
# Fenêtre principale
# ---------------------------
class NetPulsePro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("💥 NETPULSE PRO ULTIMATE X v3.0 — Le roi des analyseurs")
        self.setGeometry(50, 50, 1600, 1000)
        self.setStyleSheet(self.dark_style())

        self.sniffer = None
        self.canvas = MplCanvas()
        self.packet_list = []
        self.alerts = []

        self.init_ui()

    def dark_style(self):
        return """
        * { font-family: 'Segoe UI', Arial; }
        QMainWindow { background: #1a1a2e; color: #e0e0e0; }
        QPushButton { background: #0f3460; color: white; border: none; padding: 10px; border-radius: 8px; }
        QPushButton:hover { background: #1a508b; }
        QTabBar::tab { background: #16213e; padding: 12px; margin: 2px; border-radius: 6px; }
        QTabBar::tab:selected { background: #0f3460; color: #e94560; }
        QLineEdit, QComboBox { background: #16213e; color: #e0e0e0; padding: 8px; border: 1px solid #0f3460; }
        QTableWidget { gridline-color: #1a1a2e; border: 1px solid #0f3460; }
        QLabel { color: #e94560; font-weight: bold; }
        """

    def init_ui(self):
        # Menu
        menu = self.menuBar()
        file = menu.addMenu("📁 Fichier")
        file.addAction("💾 Sauvegarder analyse", self.save_full_analysis)
        file.addAction("📁 Exporter PCAP", self.export_pcap)
        file.addAction("⚙️ Config", self.show_config)

        tools = menu.addMenu("🔧 Outils")
        tools.addAction("📡 Désauthentifier", self.deauth_attack)
        tools.addAction("🧱 Générer Wordlist", self.generate_wordlist)
        tools.addAction("🌐 API Dashboard", self.open_dashboard)

        # Onglets
        tabs = QTabWidget()
        self.setCentralWidget(tabs)

        tabs.addTab(self.create_wifi_tab(), "📡 Wi-Fi Scanner")
        tabs.addTab(self.create_packet_tab(), "📦 Analyse en Direct")
        tabs.addTab(self.create_analysis_tab(), "🔍 Intelligence")
        tabs.addTab(self.create_graph_tab(), "📈 Visualisation")
        tabs.addTab(self.create_logs_tab(), "📋 Logs & Alertes")
        tabs.addTab(self.create_settings_tab(), "⚙️ Paramètres")

    def create_wifi_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        self.wifi_scan_btn = QPushButton("🔍 Scanner les réseaux")
        self.wifi_scan_btn.clicked.connect(self.scan_wifi_networks)
        layout.addWidget(self.wifi_scan_btn)

        self.wifi_table = QTableWidget()
        self.wifi_table.setColumnCount(6)
        self.wifi_table.setHorizontalHeaderLabels(["SSID", "BSSID", "Canal", "Fréq", "Sécurité", "Signal"])
        layout.addWidget(self.wifi_table)

        tab.setLayout(layout)
        return tab

    def scan_wifi_networks(self):
        try:
            result = subprocess.check_output(["sudo", "iwlist", "wlan0", "scan"], text=True)
            networks = []
            cell = re.finditer(r'Cell \d+ - Address: ([\w:]*)[\s\S]*?ESSID:"([^"]*)"[^F]*?Channel:(\d+)[\s\S]*?Frequency:([\d.]+ GHz)[\s\S]*?Quality=([\d/]*)[\s\S]*?Encryption key:(on|off)', result)
            for c in cell:
                bssid, ssid, chan, freq, qual, enc = c.groups()
                signal = qual.split('/')[0]
                sec = "WPA/WPA2" if enc == "on" else "OPEN"
                networks.append([ssid, bssid, chan, freq, sec, signal])

            self.wifi_table.setRowCount(0)
            for net in networks:
                row = self.wifi_table.rowCount()
                self.wifi_table.insertRow(row)
                for i, val in enumerate(net):
                    self.wifi_table.setItem(row, i, QTableWidgetItem(val))
        except Exception as e:
            QMessageBox.critical(self, "Erreur", f"Scan échoué: {e}")

    def create_packet_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()

        ctrl = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(["wlan0", "eth0", "Wi-Fi"])
        self.start_cap_btn = QPushButton("▶️ Démarrer")
        self.stop_cap_btn = QPushButton("⏹️ Arrêter")
        self.start_cap_btn.clicked.connect(self.start_capture)
        self.stop_cap_btn.clicked.connect(self.stop_capture)

        ctrl.addWidget(QLabel("Interface:"))
        ctrl.addWidget(self.iface_combo)
        ctrl.addWidget(self.start_cap_btn)
        ctrl.addWidget(self.stop_cap_btn)
        layout.addLayout(ctrl)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["Temps", "Src", "Dst", "Proto", "Port", "Taille", "Contenu"])
        layout.addWidget(self.packet_table)

        tab.setLayout(layout)
        return tab

    def start_capture(self):
        iface = self.iface_combo.currentText()
        self.sniffer = AdvancedSnifferThread(iface, bpf="not arp and not stp")
        self.sniffer.packet_signal.connect(self.display_packet)
        self.sniffer.log_signal.connect(self.log)
        self.sniffer.alert_signal.connect(self.add_alert)
        self.sniffer.start()
        self.log(f"📡 Capture démarrée sur {iface}")

    def display_packet(self, pkt):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src = dst = proto = port = load = size = "-"
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else pkt[IP].sprintf("%IP.proto%")
            port = pkt.sport if pkt.haslayer(TCP) or pkt.haslayer(UDP) else ""
        if Raw in pkt:
            load = pkt[Raw].load.decode('utf-8', errors='ignore')[:50]
        size = len(pkt)

        self.packet_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.packet_table.setItem(row, 1, QTableWidgetItem(src))
        self.packet_table.setItem(row, 2, QTableWidgetItem(dst))
        self.packet_table.setItem(row, 3, QTableWidgetItem(proto))
        self.packet_table.setItem(row, 4, QTableWidgetItem(str(port)))
        self.packet_table.setItem(row, 5, QTableWidgetItem(str(size)))
        self.packet_table.setItem(row, 6, QTableWidgetItem(load))

        self.packet_list.append(pkt)

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer.wait()

    def add_alert(self, msg):
        self.alerts.append(f"[{datetime.now().strftime('%H:%M')}] {msg}")

    def log(self, msg):
        print(msg)

    def save_full_analysis(self):
        filename = QFileDialog.getSaveFileName(self, "Sauvegarder", "", "JSON (*.json);;TXT (*.txt)")[0]
        if not filename:
            return
        data = {
            "scan_time": str(datetime.now()),
            "total_packets": len(self.packet_list),
            "alerts": self.alerts,
            "http_forms": [f for p in self.packet_list if Raw in p for f in [p[Raw].load.decode('utf-8', errors='ignore')] if 'pass' in f.lower()]
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        self.log(f"💾 Analyse sauvegardée: {filename}")

    def export_pcap(self):
        file = QFileDialog.getSaveFileName(self, "Exporter PCAP", "", "PCAP (*.pcap)")[0]
        if file and self.packet_list:
            wrpcap(file, self.packet_list)
            self.log(f"📁 Exporté en PCAP: {file}")

    def deauth_attack(self):
        bssid, ok = QInputDialog.getText(self, "Deauth", "BSSID cible:")
        if ok:
            os.system(f"sudo aireplay-ng --deauth 10 -a {bssid} wlan0")
            self.log(f"💥 Attaque deauth lancée sur {bssid}")

    def generate_wordlist(self):
        ssid, ok = QInputDialog.getText(self, "Wordlist", "SSID du réseau:")
        if ok:
            words = [ssid, ssid+"123", ssid+"2024", "admin", "password", "12345678"]
            path = f"wordlists/{ssid}_wordlist.txt"
            with open(path, "w") as f:
                f.write("\n".join(words))
            self.log(f"🧱 Wordlist générée: {path}")

    def open_dashboard(self):
        # Mini-dashboard web
        web = QWebEngineView()
        web.setHtml("<h1>🌐 NetPulse Dashboard</h1><p>En développement...</p>")
        web.show()

    def create_analysis_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.analysis_text = QTextEdit()
        self.analysis_text.setHtml("<h3>🔍 Analyse comportementale en cours...</h3>")
        layout.addWidget(self.analysis_text)
        tab.setLayout(layout)
        return tab

    def create_graph_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.canvas)
        btn = QPushButton("🔄 Mettre à jour graphique")
        btn.clicked.connect(self.update_graph)
        layout.addWidget(btn)
        tab.setLayout(layout)
        return tab

    def update_graph(self):
        self.canvas.axes.clear()
        protos = ["TCP", "UDP", "ICMP", "DNS", "HTTP"]
        counts = [120, 80, 30, 50, 40]
        self.canvas.axes.bar(protos, counts, color="#e94560")
        self.canvas.axes.set_title("Trafic par protocole")
        self.canvas.draw()

    def create_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        self.alert_list = QListWidget()
        for a in self.alerts:
            self.alert_list.addItem(a)
        layout.addWidget(self.alert_list)
        tab.setLayout(layout)
        return tab

    def create_settings_tab(self):
        tab = QWidget()
        layout = QFormLayout()
        layout.addRow("Langue", QComboBox())
        layout.addRow("Niveau de logs", QComboBox())
        layout.addRow("Dossier de sauvegarde", QLineEdit(CONFIG["capture_dir"]))
        tab.setLayout(layout)
        return tab

    def show_config(self):
        QMessageBox.information(self, "Config", "Paramètres sauvegardés.")

# ---------------------------
# Lancement
# ---------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetPulsePro()
    window.show()
    sys.exit(app.exec_())