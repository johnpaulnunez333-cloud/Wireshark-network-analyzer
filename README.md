# Wireshark Network Analyzer

A colorful terminal front-end for the real **Wireshark engine (TShark)**. It captures and decodes packets with TShark and shows them as a clean live feed with statistics, top connections, and a saved text log.

Works on **Windows, Linux, Kali, and Termux (Android)**.

## Screenshots

![Wireshark Network Analyzer menu](screenshot-1.jpg)

![Wireshark Network Analyzer running on Kali Linux](screenshot-2.jpg)

## Features

- Big gradient `WIRESHARK` banner
- Live capture powered by the real TShark process
- Monitor by URL/domain, all traffic, protocol (TCP/UDP/ICMP), or port
- Analyze `.pcap` / `.pcapng` files without root
- Live statistics and top connections
- Save the capture log to a text file

## Requirements

- Python 3.8+
- Wireshark / TShark
- `colorama` (`pip install -r requirements.txt`)

## Installation

### Linux / Kali
```bash
sudo apt install tshark python3-pip
pip install -r requirements.txt
sudo python3 wireshark.py
```

### Windows
1. Install [Wireshark](https://www.wireshark.org/download.html) (includes TShark and Npcap).
2. Install the dependency:
   ```
   pip install -r requirements.txt
   ```
3. Open Command Prompt **as Administrator** and run:
   ```
   python wireshark.py
   ```

### Termux (Android)
```bash
pkg install python tshark git
pip install -r requirements.txt
git clone https://github.com/johnpaulnunez333-cloud/Wireshark-network-analyzer
cd Wireshark-network-analyzer
python wireshark.py
```

## Root requirement

Live capture needs root privileges because the real Wireshark (TShark) process must read network interfaces.

| Environment | Live capture | Analyze `.pcap` file |
|---|---|---|
| Rooted Android (Magisk/su) | Yes | Yes |
| Non-rooted Android | No | Yes |
| Linux with `sudo` | Yes | Yes |
| Windows as Administrator | Yes | Yes |

## Usage

```
python wireshark.py
```

| Option | Action |
|---|---|
| 1 | Monitor a URL / domain |
| 2 | Monitor all traffic |
| 3 | Monitor a protocol (tcp / udp / icmp) |
| 4 | Monitor a port |
| 5 | Analyze a `.pcap` / `.pcapng` file (no root) |
| 0 | Exit |

Press `Ctrl+C` to stop a capture, then choose whether to save the log.

## Disclaimer

Use this tool only on networks and devices you own or have permission to monitor. You are responsible for how you use it.

## Author

Developed by John Paul Nunez
