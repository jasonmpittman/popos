__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2025"
__credits__ = ["Jason M. Pittman"]
__license__ = "Apache License 2.0"
__version__ = "0.3.1"
__maintainer__ = "Jason M. Pittman"
__status__ = "Beta"

#   DEFAULT SCAN OPTIONS
DEFAULT_PORT = 80
DEFAULT_SRC_PORT = 12345
DEFAULT_PORT_RANGE = (80, 80)
DELAY = 0.5
SOURCE_IP = "192.168.56.101"
DEFAULT_DST_IP = "192.168.56.101" # overridable through --target_ip cmd arg
TCP_FLAGS = ["S", "A", "F", "R", "P", "SA", "FA", "RA", "PA", ""]

#   DEFAULT GENETIC ALGORITHM OPTIONS
MIN_GENERATIONS = 1 #   if this is <> max we may not get the slealthy_individual log
MAX_GENERATIONS = 3
FITNESS_THRESHOLD = 0.98
ELITE_PERCENT = 0.05
DEFAULT_GENERATIONS = 100
DEFAULT_CROSSOVER_RATE = 0.9
DEFAULT_MUTATION_RATE = 0.5
DEFAULT_POPULATION_SIZE = 5 
DEFAULT_SWAP_RATE = 0.5
FITNESS_TIMEOUT = 10 #  30 is too slow
PAGE_COUNT = 20
PAGE_SIZE = 5
PARALLEL_EVAL = False
TOURNAMENT_SIZE = 4 #   higher causes more selection pressure

#   OPERATIONS OPTIONS
EVOLVED_SCAN_FILE = "stealthy_individual.txt"

#   LOGGING OPTIONS
POPULATION_LOGGING = True

#   SNORT INTERGRATION
SNORT_ALERT_FILE = "/var/log/snort/alert"