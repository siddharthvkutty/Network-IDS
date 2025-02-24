# Network Intrusion Detection System (NIDS)

A real-time **Network Intrusion Detection System** built with Python, designed to monitor and analyze network traffic, detect suspicious activity, and send automated alerts. Featuring a user-friendly GUI and a real-time dashboard for tracking potential threats.

## Features
- **Packet Capture**: Monitors live network traffic and captures packets.
- **Real-Time Dashboard**: Visualizes packet activity, highlighting suspicious IPs and ports.
- **Intrusion Detection Rules**:
  - Detects traffic from known malicious IPs (loaded from an external file).
  - Flags high-frequency packet traffic (DoS detection).
  - Identifies suspicious port activities (e.g., common malware ports).
  - Alerts for large packet transfers (potential data exfiltration).
- **Automated Email Alerts**: Sends notifications for detected threats.
- **GUI Interface**: Built with `tkinter` for easy use and navigation.
- **PCAP Logging**: Saves captured packets in `.pcap` format for further analysis.

## Technologies Used
- **Python 3.x**
- `scapy` - Packet capture and analysis
- `tkinter` - Graphical user interface
- `matplotlib` - Real-time dashboard visualization
- `smtplib` - Email alert system
- `dotenv` - Secure environment variable management

## Project Structure
- `Network IDS.exe` - Main executable
- `KV_pairs.env` - Environment Variables file for sensitive credentials
- `captured_packets.pcap` - File to store captured packets (generated dynamically)
- `suspicious_ips.txt` - List of known malicious IP addresses

## Setup Instructions
- **Download a release**:
  - Extract the files within the RAR folder.

- **Enter credentials in KV_pairs.env**:
    - `prog_mail`: the mail address from which the alerts will be sent
    - `prog_mailpwd`: the mail password or app password for `prog_mail`
    - `tar_mail`: mail address of the recipient of the alerts**
  
## Usage
- **Run the executable file**
 
## Licence
This project is licensed under the MIT Licence
