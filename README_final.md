# PoPOS: Polymorphic Port Scanner with Morphological Evasion

PoPOS (Polymorphic Port Scanner) is a research-grade project that evolves stealthy TCP port scans using genetic algorithms and real-time IDS feedback (Snort).

The goal is to generate scan traffic that evades detection by intrusion detection systems through dynamic adjustment of packet morphological features such as TTL, payload size, TCP flags, window size, and inter-packet delay.

---

## Features

- Genetic algorithm evolution of stealthy TCP scans
- Morphology-based stealth adaptation
- Fitness evaluation based on live Snort alerting
- Logger system with run summaries and entropy tracking
- Replay evolved scans against arbitrary targets
- Fully modular and extensible for future research

---

## Requirements

- Python 3.10+
- Scapy (`pip install scapy`)
- Snort IDS (tested with Snort 2.9.20)

Recommended:
- Virtualized testbed environment
- Access to modify Snort rules for experimentation

---

## Setup Instructions

### 1. Build at least two virtual machines
- VM1: Scanner (runs PoPOS)
- VM2: IDS Target (runs Snort)

Ensure both are reachable on the same Layer 2 network (bridged adapter recommended).

### 2. Install Snort on the Target VM
```bash
sudo apt update
sudo apt install snort
```

Configure Snort:
```bash
sudo snort -i eth0 -c /etc/snort/snort.conf -A fast -l /var/log/snort
```

Run Snort:
```bash
sudo snort -i eth0 -c /etc/snort/snort.conf -A fast -l /var/log/snort
```

(Optional) Tail alerts in real-time:
```bash
sudo tail -f /var/log/snort/alert
```

---

## Usage

Activate your Python environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy
```

Clone the repository and navigate into it:

```bash
git clone <your_repo_url>
cd popos
```

Basic SYN Scan:

```bash
python3 popos.py --target 192.168.x.x --scan_type basic
```

Evolve a Stealth Scan (Genetic Algorithm):

```bash
python3 popos.py --target 192.168.x.x --scan_type genetic
```

Replay an Evolved Scan:

```bash
python3 popos.py --target 192.168.x.x --scan_type replay --replay_file logs/experiment_<timestamp>/stealthy_individual_genX.txt
```

---

## Notes on Potential Errors

### Scapy "Module Not Found" during `sudo`:

If you see:

```bash
ModuleNotFoundError: No module named 'scapy'
```

It is due to `sudo` losing the Python `site-packages` from your virtual environment.

Fix by running:

```bash
sudo ./venv/bin/python3 popos.py --target ...
```

(Explicitly call the correct Python interpreter.)

---

## Directory Structure

```plaintext
popos/
├── config.py        # Configuration and constants
├── ga.py            # Genetic algorithm core
├── packet.py        # Packet crafting and sending
├── popos.py         # Main launcher
├── replay.py        # Replay engine
├── logger.py        # Logging utilities
├── README.md        # This file
├── logs/            # Output logs organized per run
│   └── experiment_<timestamp>/
│       ├── run_summary.json
│       ├── entropy_log.json
│       └── stealthy_individual_genX.txt
```

---

## Acknowledgments

This project builds on ideas from prior research in polymorphic scanning and morphological IDS evasion, particularly adapting concepts from:

- LaRoche et al. (2009), "Polymorphic Scanning of Port-Based Intrusion Detection Systems"
- Alani et al. (2023), "Analysis of Morphological Features for Stealth Scans"

---

## Disclaimer

This project is intended for **educational and research purposes only**.  
Always scan only devices and networks you own or have explicit permission to test.

---

## License

PoPOS is distributed under the **GNU General Public License v3.0 (GPLv3)**.

See [LICENSE](LICENSE) for full license text.