__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2025"
__credits__ = ["Jason M. Pittman"]
__license__ = "Apache License 2.0"
__version__ = "0.3.1"
__maintainer__ = "Jason M. Pittman"
__status__ = "Beta"

"""
popos.py - Main Launcher for Polymorphic Port Scanner

Handles CLI arguments, initializes scans (basic, genetic, replay), and orchestrates system components.

Responsibilities:
- Parse command-line arguments
- Initialize and run basic scans
- Initialize and evolve stealth scans via genetic algorithm
- Replay evolved scans against targets
"""

from logger import Logger
from packet import Packet
from replay import Replay
from ga import Population, evolve_population

import argparse
import config
from scapy.all import IP, TCP, sr

def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        tuple: (target_ip, port_range, scan_type, replay_file, pop_size)
    """

    parser = argparse.ArgumentParser(description="GP-based TCP/IP Port Scanner")
    
    parser.add_argument("--target", required=True, help="Target IP address to scan (required).")
    parser.add_argument("--ports", default=str(config.DEFAULT_PORT),
                        help="Target port or port range to scan (e.g., '80' or '20-80'). Default: 80")
    parser.add_argument("--scan_type", default="basic", help="Define the type of scan as basic or genetic. Default: basic")
    parser.add_argument("--replay_file", help="Required if scan_type if 'reply'")
    parser.add_argument("--pop_size", type=int, default=config.DEFAULT_POPULATION_SIZE,
                        help=f"Population size for GP. Default: {config.DEFAULT_POPULATION_SIZE}")
    
    args = parser.parse_args()

    #   replay_file check for scan_type == replay
    if args.scan_type == 'replay' and not args.replay_file:
        parser.error('--replay_file is required when --scan_type is replay')
    elif args.replay_file and not args.scan_type == 'replay':
        parser.error('--replay_file cannot be used unless --scan_type is replay')

    #   Parse port range
    if "-" in args.ports:
        start_port, end_port = map(int, args.ports.split("-"))
    else:
        start_port = end_port = int(args.ports)

    port_range = (start_port, end_port)
    
    return args.target, port_range, args.scan_type, args.replay_file, args.pop_size

def setup_environment(pop_size, port_range, target_ip):
    print(f"[+] PoPOS Configuration:")
    print(f"    Target IP: {target_ip}")
    print(f"    Port Range: {port_range[0]} - {port_range[1]}")
    print(f"    Population Size: {pop_size}")
    print(f"    Generations: {config.DEFAULT_GENERATIONS}")
    print(f"    Crossover Rate: {config.DEFAULT_CROSSOVER_RATE}")
    print(f"    Mutation Rate: {config.DEFAULT_MUTATION_RATE}")
    print(f"    Swap Rate: {config.DEFAULT_SWAP_RATE}")

def scan_basic(target_ip: str, target_port: int) -> str:
    """
    Perform a basic SYN scan against a single port.

    Args:
        target_ip (str): Target IP address.
        target_port (int): Target port.
    """

    print(f"Scanning {target_ip} for open ports...")
    #for port in self.ports:
    # indent below if port is collection
    response = sr(IP(dst=target_ip)/TCP(dport=target_port, flags="S"), timeout=1, verbose=0)[0]
    if response:
        for sent, received in response:
            if received.haslayer(TCP) and received[TCP].flags == 18:  # SYN-ACK
                print(f"Port {target_port} is open")
            elif received.haslayer(TCP) and received[TCP].flags == 20:  # RST
                print(f"Port {target_port} is closed")
    else:
        print(f"Port {target_port} is filtered or no response")

def main():
    target_ip, port_range, scan_type, replay_file, pop_size = parse_arguments()
    
    #   basic scan is just a SYN scan against target and port range
    if scan_type == 'basic':
        if port_range[0] == port_range[1]:
            scan_basic(target_ip, port_range[0])
        else:
            for target_port in range(port_range[0], port_range[1]):
                scan_basic(target_ip, target_port)
    
    #   genetic scan attempts to evolve a stealthy scan
    if scan_type == 'genetic':
        setup_environment(pop_size, port_range, target_ip)
        population = Population(pop_size, target_ip, port_range)
        population.summary()

        logger = Logger(experiment_name="ttl_morphology_test")
        logger.log_metadata(
            target_ip=target_ip,
            port_range=port_range,
            population_size=pop_size,
            generations=config.DEFAULT_GENERATIONS,
            mutation_rate=config.DEFAULT_MUTATION_RATE,
            crossover_rate=config.DEFAULT_CROSSOVER_RATE
        )

        if config.POPULATION_LOGGING:
            evolve_population(population, logger=logger)
        else:
            evolve_population(population)


        logger.export_logs()
    
    #   replay a successful evolved stealthy scan to intended target
    if scan_type == 'replay':
        rep = Replay(instruction_file=replay_file, target_ip=target_ip, target_ports=port_range)
        rep.run()

if __name__ == "__main__":
    main()