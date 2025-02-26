import os
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from dotenv import load_dotenv
from scapy.all import sniff, wrpcap, rdpcap, IP
import smtplib
import time
import socket
import matplotlib.pyplot as plt  # 📊 Added for real-time dashboard graphs
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg  # 📊 Embed graphs in Tkinter

# Load environment variables
load_dotenv("KV_pairs.env")
prog_mail = os.getenv("prog_mail")
prog_mailpwd = os.getenv("prog_mailpwd")
tar_mail = os.getenv("tar_mail")

# Read email credentials
EMAIL_ADDRESS = prog_mail
EMAIL_PASSWORD = prog_mailpwd
ALERT_EMAIL = tar_mail

# GUI Setup
root = tk.Tk()
root.title("Network Intrusion Detection System with Real-Time Dashboard")  # 📊 Updated title
root.geometry("1280x720")  # 📊 Increased size for dashboard

# Capture Config
PCAP_FILE = "captured_packets.pcap"

# Function to load suspicious IPs from a file into a dictionary
def load_suspicious_ips(file_path):
    suspicious_ips = {}
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip:
                    suspicious_ips[ip] = "Suspicious"
    else:
        print("File not found!")
    return suspicious_ips

# Define known suspicious IPs
SUSPICIOUS_IPS = load_suspicious_ips("suspicious_ips.txt")

# Define known bad ports
SUSPICIOUS_PORTS = {4444, 6667, 1337, 8080, 23, 22}

# Track packet frequency
packet_counts = {}

# 📊 Dashboard Stats Variables
total_packets_captured = 0
suspicious_packets_detected = 0

# UI Log Box
log_text = scrolledtext.ScrolledText(root, width=100, height=20)

# 📊 Dashboard Labels
dashboard_frame = tk.Frame(root)
packet_label = tk.Label(dashboard_frame, text="Total Packets Captured: 0", font=("Helvetica", 12))
suspicious_label = tk.Label(dashboard_frame, text="Suspicious Packets Detected: 0", font=("Helvetica", 12))

# 📊 Real-Time Graph Setup
fig, ax = plt.subplots(figsize=(5, 3))
canvas = FigureCanvasTkAgg(fig, master=dashboard_frame)
canvas_widget = canvas.get_tk_widget()

def update_graph():
    ax.clear()
    ax.set_title("Packet Count per IP")
    ax.set_xlabel("IP Address")
    ax.set_ylabel("Packet Count")
    if packet_counts:
        ips = list(packet_counts.keys())
        counts = list(packet_counts.values())
        ax.bar(ips, counts, color='skyblue')
        plt.xticks(rotation=360, ha='right')
        plt.tight_layout()
    canvas.draw()

# Start Packet Capture
def start_capture():
    log_text.insert(tk.END, "\n🔴 Checking network activity...\n")
    log_text.see(tk.END)  # Auto-scroll
    selected_if = selected_interface.get()

    def capture():
        global total_packets_captured  # 📊 Update total packets
        
        try:
            # Quick network activity check
            test_packets = sniff(iface=selected_if, timeout=2, count=5)
            
            if not test_packets:  # 🚨 No packets detected, show error message
                messagebox.showerror("Error", f"No network activity detected on {selected_if}.")
                log_text.insert(tk.END, f"⚠️ No network activity detected on {selected_if}.\n")
                log_text.see(tk.END)  # Auto-scroll
                return  # Stop function

            log_text.insert(tk.END, "✅ Network activity detected! Starting full packet capture...\n")
            log_text.see(tk.END)  # Auto-scroll

        except Exception as e:
            messagebox.showerror("Error", f"Failed to check network activity: {e}")
            log_text.insert(tk.END, f"❌ Failed to check network activity: {e}\n")
            log_text.see(tk.END)  # Auto-scroll
            return  # Stop function
        
        # If network activity is detected, proceed with full capture
        try:
            packets = sniff(iface=selected_if, count=150, prn=log_packet)
            
            total_packets_captured += len(packets)
            packet_label.config(text=f"Total Packets Captured: {total_packets_captured}")
            wrpcap(PCAP_FILE, packets)
            log_text.insert(tk.END, f"✅ Packets saved to {PCAP_FILE}\n")
            log_text.see(tk.END)  # Auto-scroll
            update_graph()  # 📊 Update graph after capture

        except Exception as e:
            messagebox.showerror("Error", f"Failed to capture packets: {e}")
            log_text.insert(tk.END, f"❌ Failed to capture packets: {e}\n")
            log_text.see(tk.END)  # Auto-scroll

    threading.Thread(target=capture, daemon=True).start()

# Function to log packets with auto-scroll
def log_packet(p):
    log_text.insert(tk.END, f"Captured: {p.summary()}\n")
    log_text.see(tk.END)  # Auto-scroll

# Function to log packets with auto-scroll
def log_packet(p):
    log_text.insert(tk.END, f"Captured: {p.summary()}\n")
    log_text.see(tk.END)  # Auto-scroll

# Analyze Packets
def analyze_packets():
    log_text.insert(tk.END, "\n🔍 Analyzing packets...\n")

    def analyze():
        global suspicious_packets_detected  # 📊 Update suspicious count
        time.sleep(2)
        packets = rdpcap(PCAP_FILE)
        mal_found = 0
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1

                if src_ip in SUSPICIOUS_IPS:
                    alert_msg = f"🚨 WARNING: Traffic from a known malicious IP {src_ip} to {dst_ip}!"
                    log_text.insert(tk.END, alert_msg + "\n")
                    mal_found = 1
                    suspicious_packets_detected += 1
                    send_alert("Suspicious IP Alert", alert_msg)

                if packet_counts[src_ip] > 50:
                    alert_msg = f"🚨 Possible DoS Attack: {src_ip} sent {packet_counts[src_ip]} packets!"
                    log_text.insert(tk.END, alert_msg + "\n")
                    mal_found = 1
                    suspicious_packets_detected += 1
                    send_alert("DoS Attack Alert", alert_msg)

                if packet.haslayer("TCP") and packet["TCP"].dport in SUSPICIOUS_PORTS:
                    alert_msg = f"⚠️ Suspicious Port Activity: {src_ip} -> {dst_ip} on port {packet['TCP'].dport}"
                    log_text.insert(tk.END, alert_msg + "\n")
                    mal_found = 1
                    suspicious_packets_detected += 1
                    send_alert("Suspicious Port Activity", alert_msg)

                if len(packet) > 10000:
                    alert_msg = f"⚠️ Large Packet Detected: {len(packet)} bytes from {src_ip} to {dst_ip}"
                    log_text.insert(tk.END, alert_msg + "\n")
                    mal_found = 1
                    suspicious_packets_detected += 1
                    send_alert("Large Packet Alert", alert_msg)

        suspicious_label.config(text=f"Suspicious Packets Detected: {suspicious_packets_detected}")
        update_graph()  # 📊 Update graph after analysis

        log_text.insert(tk.END, "✅ Analysis complete.\n")
        if mal_found == 0:
            log_text.insert(tk.END, f"No suspicious activity found in {len(packets)} packets.\n")
        else:
            log_text.insert(tk.END, f"Suspicious activity detected in {len(packets)} packets. Alerts sent.\n")

    threading.Thread(target=analyze, daemon=True).start()

# Send Alert Email
def send_alert(subject, message):
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            email_message = f"Subject: {subject}\n\n{message}".encode("utf-8")
            server.sendmail(EMAIL_ADDRESS, ALERT_EMAIL, email_message)
            log_text.insert(tk.END, "📧 Alert email sent!\n")
    except Exception as e:
        log_text.insert(tk.END, f"❌ Failed to send email: {e}\n")

# Exit Program
def exit_program():
    if messagebox.askokcancel("Exit", "Are you sure you want to exit?"):
        root.destroy()

# UI Buttons
btn_frame = tk.Frame(root)
start_btn = tk.Button(btn_frame, text="Start Capture", command=start_capture, bg="green", fg="white")
analyze_btn = tk.Button(btn_frame, text="Analyze Packets", command=analyze_packets, bg="blue", fg="white")
exit_btn = tk.Button(btn_frame, text="Exit Program", command=exit_program, bg="red", fg="white")
# Dropdown menu for selecting network interface
selected_interface = tk.StringVar(root)
selected_interface.set("Wi-Fi")  # Default selection
interface_menu = tk.OptionMenu(btn_frame, selected_interface, "Wi-Fi", "Wi-Fi 2", "Ethernet", "Ethernet 2")

# Layout
btn_frame.pack(pady=10)
interface_menu.pack(side=tk.LEFT, padx=10)
start_btn.pack(side=tk.LEFT, padx=10)
analyze_btn.pack(side=tk.LEFT, padx=10)
exit_btn.pack(side=tk.LEFT, padx=10)
log_text.pack(pady=5)

# 📊 Dashboard Layout
packet_label.pack(anchor='w', pady=2)
suspicious_label.pack(anchor='w', pady=2)
canvas_widget.pack(fill=tk.BOTH, expand=True)
dashboard_frame.pack(pady=10, fill=tk.BOTH, expand=True)

# Start GUI Loop
root.mainloop()