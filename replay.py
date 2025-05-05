__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2025"
__credits__ = ["Jason M. Pittman"]
__license__ = "Apache License 2.0"
__version__ = "0.3.1"
__maintainer__ = "Jason M. Pittman"
__status__ = "Beta"

"""
replay.py - Replay Engine for Stealthy Port Scans

Loads a previously evolved stealthy individual and replays the packet sequence against a target.

Responsibilities:
- Load evolved individuals from file.
- Override target IP and ports if needed.
- Send packets and classify responses.
- Print a clean replay summary.
"""

from packet import Packet

import ast
import config
import time

def load_individual(filename):
    """
    Loads an individual's genome from file for replay

    Args:
        filename (str): Path to the saved individual file.

    Returns:
        list: Genome (list of (instruction, parameter) tuples)
    """

    instructions = []

    with open(filename, "r") as f:
        for line in f:
            instructions.append(ast.literal_eval(line.strip()))
    
    return instructions

class Replay:
    """
    Class to replay a stealthy scan based on a loaded individual.
    Tracks packet classifications (open, closed, filtered, unknown).
    """

    def __init__(self, instruction_file, target_ip, target_ports=None):
        """
        Initialize Replay.

        Args:
            instruction_file (str): Path to saved genome.
            target_ip (str, optional): Override destination IP.
            target_ports (int or tuple, optional): Override destination port(s).
        """

        self.instruction_file = instruction_file
        self.target_ip = target_ip
        self.target_ports = target_ports
        self.results = {"open": 0, "closed": 0, "filtered": 0, "unknown": 0}
        self.packet = Packet()
        self.delay = config.DELAY

    def run(self):
        """
        Replays the packet sequence against the target and classifies responses.
        """

        print(f"[+] Replaying scan against {self.target_ip}")
        instructions = load_individual(self.instruction_file)

        for instr, param in instructions:
            if instr == "set_flags":
                self.packet.set_flags(param)
            elif instr == "set_ports":
                src, dst = param
                dst = self.target_ports if self.target_ports else dst
                self.packet.set_ports(src, dst) 
            elif instr == "set_ips":
                src, _ = param
                self.packet.set_ips(config.SOURCE_IP, self.target_ip)
            elif instr == "send_packet":
                result = self.packet.replay_and_classify_packet(
                    override_dst_ip=self.target_ip,
                    override_dst_port=self.packet.dst_port,
                    verbose=True
                )
                if result:
                    self.results[result] += 1
            time.sleep(self.delay)

        self.print_summary()

    def print_summary(self):
        """
        Prints a summary of the replay results.
        """
        print("\n=== Replay Summary ===")
        for k, v in self.results.items():
            print(f"{k.capitalize():>9}: {v} packets")