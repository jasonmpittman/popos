__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2025"
__credits__ = ["Jason M. Pittman"]
__license__ = "Apache License 2.0"
__version__ = "0.3.1"
__maintainer__ = "Jason M. Pittman"
__status__ = "Beta"

"""
packet.py - Packet Crafting and Transmission Engine

Handles creation, customization, and sending of packets.
Supports dynamic field mutation and stealthy replay classification.

Responsibilities:
- Create base TCP/IP packets
- Allow field mutations (flags, TTL, window size, payload length, IP flags)
- Send packets
- Replay packets and classify responses (open/closed/filtered/unknown)
"""

import time
import config
from scapy.all import IP, TCP, send, sr1

class Packet:
    """
    Represents a network packet for scanning or replay.
    """

    def __init__(self):
        """
        Initializes with default safe values.
        """

        self.src_ip = config.SOURCE_IP # Default source IP; can be randomized or customized
        self.dst_ip = config.DEFAULT_DST_IP
        self.src_port = config.DEFAULT_SRC_PORT          # Default source port; can be randomized
        self.dst_port = config.DEFAULT_PORT
        self.delay = config.DELAY
        self.flags = "S"               # Default TCP flag set to SYN

    #   base polymorhpic features
    def set_flags(self, flags):
        """Set TCP flags (e.g., SYN, ACK, FIN)."""
        self.flags = flags

    def set_ips(self, src_ip, dst_ip):
        """Set the source and destination IP addresses."""
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def set_ports(self, src_port, dst_port):
        """Set the source and destination TCP ports."""
        self.src_port = src_port
        self.dst_port = dst_port

    #   advanced polymorphic features
    def set_ttl(self, ttl):
        self.ttl = ttl

    def set_window_size(self, window_size):
        self.window_size = window_size

    def set_payload_length(self, length):
        self.payload_length = length

    def set_ip_flags(self, flags):
        self.ip_flags = flags  # 'DF', 'MF', or ''

    def set_delay(self, seconds):
        self.delay = seconds

    def build_packet(self):
        """
        Constructs a TCP/IP packet based on current attributes.

        Returns:
            Scapy packet object
        """
        
        if self.dst_ip is None or self.dst_port is None:
            raise ValueError("Destination IP and port must be set before sending.")

        ip_flags = 0
        if hasattr(self, 'ip_flags'):
            if self.ip_flags == "DF":
                ip_flags = 'DF'
            elif self.ip_flags == "MF":
                ip_flags = 'MF'

        ip_layer = IP(src=self.src_ip, dst=self.dst_ip, ttl=getattr(self, 'ttl', 64), flags=ip_flags)
        tcp_layer = TCP(
            sport=self.src_port,
            dport=self.dst_port,
            flags=self.flags,
            window=getattr(self, 'window_size', 8192)
        )

        payload = b"A" * getattr(self, 'payload_length', 0)
        
        
        return ip_layer / tcp_layer / payload

    def send_packet(self, verbose=False):
        """
        Sends the built packet.

        Args: 
            verbose (bool): Whether to print sending information.
        """
              
        packet = self.build_packet()

        send(packet, verbose=False)

        delay = getattr(self, 'delay', 0)
        if delay > 0:
            time.sleep(delay)


    def replay_and_classify_packet(self, override_dst_ip=None, override_dst_port=None, verbose=False):
        """
        Sends a packet and classifies the target's response.

        Args:
            override_dst_ip (str): Override destination IP in replay file with cmd arg value
            override_dst_port (int): Override destination TCP port in replay file with cmd arg value
            verbose (bool): Whether to print the classification.

        Returns:
            str: One of "open", "closed", "filtered", "unknown"
        """
        dst_ip = override_dst_ip if override_dst_ip else self.dst_ip
        dst_port = override_dst_port if override_dst_port else self.dst_port

        if dst_ip is None or dst_port is None:
            raise ValueError("Destination IP and port must be set before replaying.")

        packet = IP(src=self.src_ip, dst=dst_ip) / \
                TCP(sport=self.src_port, dport=dst_port, flags=self.flags)

        response = sr1(packet, timeout=1, verbose=0)

        if verbose:
            print(f"[DEBUG] Sent: {self.src_ip}:{self.src_port} → {dst_ip}:{dst_port} [Flags: {self.flags}]")
            if response:
                print(f"[DEBUG] Received: {response.summary()}")
            else:
                print("[DEBUG] No response received.")

        # Classification logic
        if not response:
            return "filtered"
        elif response.haslayer(TCP):
            if response[TCP].flags == "SA":
                return "open"
            elif response[TCP].flags == "RA":
                return "closed"

        return "unknown"