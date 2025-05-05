__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2025"
__credits__ = ["Jason M. Pittman"]
__license__ = "Apache License 2.0"
__version__ = "0.3.1"
__maintainer__ = "Jason M. Pittman"
__status__ = "Beta"

"""
ga.py - Genetic Algorithm Core for PoPOS

Handles population initialization, selection, crossover, mutation, and
evolution of stealthy scan packets against intrusion detection systems.
"""

from packet import Packet

import copy
import random
import config

#   Global variable for Snort integration offset
_snort_alert_offset = 0

class Individual:
    """
    Represents an individual in the population.
    """

    def __init__(self, target_ip, port_range):
        self.target_ip = target_ip
        self.port_range = port_range
        self.instructions = self.random_instructions()
        self.fitness = 0

    def random_instructions(self):
        """
        Generates a random sequence of packet instructions for this individual.
        """

        instructions = []

        #   Always start with safe defaults
        instructions = [
            #   base features
            ("set_flags", random.choice(config.TCP_FLAGS)),
            ("set_ips", ("192.168.1." + str(random.randint(1, 254)), self.target_ip)),
            ("set_ports", (random.randint(1024, 65535),
                        random.randint(self.port_range[0], self.port_range[1]))),
            
            #   advanced features
            ("set_ttl", random.randint(32, 128)),
            ("set_window_size", random.randint(0, 65535)),
            ("set_payload_length", random.randint(0, 1500)),
            ("set_ip_flags", random.choice(["DF", "MF", ""])),
            ("set_delay", round(random.uniform(0.0, 2.0), 2))  # in seconds
        ]
        # Now append randomized instruction mix
        for _ in range((config.PAGE_COUNT * config.PAGE_SIZE) - len(instructions)):
            instr = random.choice([
                #   base features
                ("set_flags", random.choice(config.TCP_FLAGS)),
                ("set_ips", ("192.168.1." + str(random.randint(1,254)), self.target_ip)),
                ("set_ports", (random.randint(1024, 65535),
                               random.randint(self.port_range[0], self.port_range[1]))),
                #   advanced features               
                ("set_ttl", random.randint(32, 128)),
                ("set_window_size", random.randint(0, 65535)),
                ("set_payload_length", random.randint(0, 1500)),
                ("set_ip_flags", random.choice(["DF", "MF", ""])),
                ("set_delay", round(random.uniform(0.0, 2.0), 2)),

                #   base send
                ("send_packet", None)
            ])  
            instructions.append(instr)
        random.shuffle(instructions)  # optional: add more chaos

        return instructions

class Population:
    """
    Represents the entire population of individuals.
    """

    def __init__(self, size, target_ip, port_range):
        self.individuals = [Individual(target_ip, port_range) for _ in range(size)]

    def summary(self):
        print(f"[+] Initialized population with {len(self.individuals)} individuals.")
        print(f"[+] Example individual (first 5 instructions):")
        for instr in self.individuals[0].instructions[:5]:
            print(f"    {instr}")


def get_snort_alert_count():
    """
    Reads the Snort alert file and returns the number of new alerts.
    """

    global _snort_alert_offset
    alert_path = config.SNORT_ALERT_FILE

    try:
        with open(alert_path, "r") as f:
            f.seek(_snort_alert_offset)       # go to last known offset
            new_alerts = f.readlines()        # read only new content
            _snort_alert_offset = f.tell()    # update offset
            return len(new_alerts)
    except FileNotFoundError:
        print("[WARNING] Snort alert log not found.")
        return 0

def evaluate_fitness(individual, generation, index, logger=None):
    """
    Evaluates the fitness of a single individual based on alert triggering and morphology.
    """

    packet = Packet()
    print(f"[DEBUG] Evaluating individual...")

    alerts_before = get_snort_alert_count()

    #   Track morphological attributes
    ttl_values = []
    payload_lengths = []
    window_sizes = []
    delays = []

    sent_packets = 0

    for instruction, param in individual.instructions:
        if instruction == "set_flags":
            packet.set_flags(param)
        elif instruction == "set_ips":
            packet.set_ips(*param)
        elif instruction == "set_ports":
            packet.set_ports(*param)
        elif instruction == "set_ttl":
            packet.set_ttl(param)
            ttl_values.append(param)
        elif instruction == "set_window_size":
            packet.set_window_size(param)
            window_sizes.append(param)
        elif instruction == "set_payload_length":
            packet.set_payload_length(param)
            payload_lengths.append(param)
        elif instruction == "set_ip_flags":
            packet.set_ip_flags(param)
        elif instruction == "set_delay":
            packet.set_delay(param)
            delays.append(param)
        elif instruction == "send_packet":
            try:
                packet.send_packet(verbose=False)
                sent_packets += 1
            except Exception as e:
                print(f"[ERROR] send_packet failed: {e}")
                continue

    alerts_after = get_snort_alert_count()
    alerts_triggered = alerts_after - alerts_before

    if sent_packets == 0:
        print("[DEBUG] No packets were sent.")
        individual.fitness = 0.0
        return 0.0

    base_fitness = 1 - (alerts_triggered / sent_packets)

    #   Morphology-based stealth bonus
    avg_ttl = sum(ttl_values) / len(ttl_values) if ttl_values else 0
    avg_payload = sum(payload_lengths) / len(payload_lengths) if payload_lengths else 0
    avg_window = sum(window_sizes) / len(window_sizes) if window_sizes else 65535
    avg_delay = sum(delays) / len(delays) if delays else 0

    bonus = 0
    if avg_ttl > 64: bonus += 0.05
    if avg_payload > 200: bonus += 0.05
    if avg_window < 5000: bonus += 0.05
    if avg_delay >= 0.5: bonus += 0.05

    #   Flag penalties
    flag_hist = [val for instr, val in individual.instructions if instr == "set_flags"]
    flag_penalty = 0
    flag_penalty += flag_hist.count("") * 0.01
    flag_penalty += flag_hist.count("F") * 0.01
    flag_penalty += flag_hist.count("SF") * 0.02
    flag_penalty += flag_hist.count("RA") * 0.02
    flag_penalty += flag_hist.count("SA") * 0.02
    flag_penalty += flag_hist.count("FA") * 0.02
    flag_penalty += flag_hist.count("PA") * 0.01

    #   Flag entropy bonus (diversity encouragement)
    unique_flags = set(flag_hist)
    flag_entropy = len(unique_flags) / len(flag_hist) if flag_hist else 0
    entropy_bonus = 0.05 * flag_entropy

    #   Final fitness score
    total_fitness = max(min(base_fitness + bonus + entropy_bonus - flag_penalty, 1.0), 0.0)
    individual.fitness = total_fitness

    individual.stats = {
        "alerts": alerts_triggered,
        "packets": sent_packets,
        "ttl_avg": avg_ttl,
        "payload_avg": avg_payload,
        "window_avg": avg_window,
        "delay_avg": avg_delay
    }

    if total_fitness == 0.0:
        print(f"[DEBUG] Zero fitness. Alerts: {alerts_triggered}, Packets: {sent_packets}, TTL: {avg_ttl}, Delay: {avg_delay}, Flags: {flag_hist}")

    print(f"[DEBUG] Flag entropy: {flag_entropy:.3f}, Entropy bonus: {entropy_bonus:.4f}, Penalty: {flag_penalty:.4f}")

    if logger:
        logger.log_entropy(
            generation, index, total_fitness, flag_entropy, entropy_bonus, flag_penalty, flag_hist
    )

    return total_fitness

def evaluate_population(population, generation, logger=None):
    """
    Evaluates the fitness of all individuals in the population sequentially.
    """

    fitnesses = []

    for i, individual in enumerate(population.individuals):
        #   for debugging if an individual is stuck
        print(f"  -> Evaluating individual {i + 1}/{len(population.individuals)}")
        fitness = evaluate_fitness(individual, generation, i, logger=logger)
        fitnesses.append(fitness)
    
    best = max(population.individuals, key=lambda ind: ind.fitness)
    avg = sum([ind.fitness for ind in population.individuals]) / len(population.individuals)
    print(f"[GENERATION {generation}] Best fitness: {best.fitness:.4f} | Avg fitness: {avg:.4f}")

    return fitnesses

def central_fitness_controller(population, timeout=15):
    """
    Centralized evaluation to avoid multiprocessing offset sharing issues with Snort logs.
    Each individual is evaluated sequentially in the parent process with timeout enforcement.
    """
    from multiprocessing import Pool, TimeoutError

    fitnesses = []
    for i, individual in enumerate(population.individuals):
        print(f"[GEN {i}] Evaluating individual {i+1}/{len(population.individuals)}")
        try:
            # Setup a process pool to apply timeout to a single evaluation
            with Pool(1) as pool:
                result = pool.apply_async(evaluate_fitness, (individual,))
                fitness = result.get(timeout=timeout)
                fitnesses.append(fitness)
        except TimeoutError:
            print(f"[WARNING] Individual {i} timed out.")
            fitnesses.append(0.0)
        except Exception as e:
            print(f"[ERROR] Evaluation failed: {e}")
            fitnesses.append(0.0)

    return fitnesses

def crossover(parent1, parent2):
    """
    Performs one-point crossover between two parents.
    """

    child1 = copy.deepcopy(parent1)
    child2 = copy.deepcopy(parent2)

    page_size = 6  # From your config
    num_pages = len(parent1.instructions) // page_size
    crossover_point = random.randint(0, num_pages - 1)

    # Calculate start and end index of the page
    start = crossover_point * page_size
    end = start + page_size

    # Swap one page between children
    child1.instructions[start:end], child2.instructions[start:end] = \
        child2.instructions[start:end], child1.instructions[start:end]

    return child1, child2

def mutate(individual, current_gen, max_gen):
    """
    Mutates an individual's genome based on mutation rate.
    """

    mutation_prob = config.DEFAULT_MUTATION_RATE * (1 - (current_gen / max_gen))

    for i in range(len(individual.instructions)):
        if random.random() < mutation_prob:
            instr = random.choice([
                ("set_flags", random.choice(config.TCP_FLAGS)),
                ("set_ips", ("192.168.1." + str(random.randint(1, 254)), individual.target_ip)),
                ("set_ports", (
                    random.randint(1024, 65535),
                    random.randint(individual.port_range[0], individual.port_range[1])
                )),
                ("send_packet", None)
            ])
            individual.instructions[i] = instr
    return individual

def swap(individual):
    """
    Randomly swaps two genes in an individual's genome.
    """

    i, j = random.sample(range(len(individual.instructions)), 2)
    individual.instructions[i], individual.instructions[j] = individual.instructions[j], individual.instructions[i]
    return individual

def tournament_selection(population, tournament_size=4):
    """
    Selects two parents using tournament selection.
    """

    competitors = random.sample(population, tournament_size)
    sorted_competitors = sorted(competitors, key=lambda ind: ind.fitness, reverse=True)
    return sorted_competitors[0], sorted_competitors[1]

def evolve_population(population, logger=None):
    """
    Evolves the population across multiple generations to find stealthy scans.
    """

    for generation in range(config.MAX_GENERATIONS):
        print(f"\n[GENERATION {generation}]")
        print(f"[GENERATION {generation}] Evaluating fitness...")

        if config.PARALLEL_EVAL:
            fitnesses = central_fitness_controller(population, timeout=config.FITNESS_TIMEOUT)
        else:
            fitnesses = evaluate_population(population, generation, logger=logger)

        print(f"[GENERATION {generation}] Fitness evaluation complete.")

        avg_fitness = sum(fitnesses) / len(fitnesses)
        best = max(population.individuals, key=lambda ind: ind.fitness)

        print(f"[+] Best fitness: {best.fitness:.4f}")
        print(f"[+] Avg fitness: {avg_fitness:.4f}")

        if logger:
            logger.log_generation(
                generation=generation,
                best_fitness=best.fitness,
                avg_fitness=avg_fitness,
                best_alerts=getattr(best, "stats", {}).get("alerts", 0),
                best_packets=getattr(best, "stats", {}).get("packets", 0),
                ttl_avg=getattr(best, "stats", {}).get("ttl_avg", 0),
                payload_avg=getattr(best, "stats", {}).get("payload_avg", 0),
                window_avg=getattr(best, "stats", {}).get("window_avg", 0),
                delay_avg=getattr(best, "stats", {}).get("delay_avg", 0)
            )

        if best.fitness >= config.FITNESS_THRESHOLD and generation >= config.MIN_GENERATIONS:
            print(f"[!!!] Stealth scan evolved in generation {generation}")
            save_individual(best, f"stealthy_individual_gen{generation}.txt")
            if logger:
                logger.save_individual(best, generation)
            break

        # Select elites (top 5%)
        elite_count = max(1, int(len(population.individuals) * config.ELITE_PERCENT))
        elites = sorted(population.individuals, key=lambda i: i.fitness, reverse=True)[:elite_count]

        # Generate next generation with elitism + operators
        new_individuals = elites[:]
        while len(new_individuals) < len(population.individuals):
            parent1, parent2 = tournament_selection(population.individuals, config.TOURNAMENT_SIZE)
            child1, child2 = crossover(parent1, parent2)
            child1 = mutate(child1, generation, config.MAX_GENERATIONS)
            child2 = mutate(child2, generation, config.MAX_GENERATIONS)
            child1 = swap(child1)
            child2 = swap(child2)
            new_individuals.extend([child1, child2])

        population.individuals = new_individuals[:len(population.individuals)]

def save_individual(ind, filename=config.EVOLVED_SCAN_FILE):
    """
    Saves an individual's instructions to a file.

    Args:
        individual (Individual): The evolved stealthy individual.
        filename (str): Output filename.
    """

    with open(filename, "w") as f:
        for instr in ind.instructions:
            f.write(f"{instr}\n")
