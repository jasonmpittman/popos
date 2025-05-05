__author__ = "Jason M. Pittman"
__copyright__ = "Copyright 2025"
__credits__ = ["Jason M. Pittman"]
__license__ = "Apache License 2.0"
__version__ = "0.3.0"
__maintainer__ = "Jason M. Pittman"
__status__ = "Beta"

import json
import os
import datetime

class Logger:
    def __init__(self, log_dir="logs", experiment_name="experiment"):
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.log_dir = os.path.join(log_dir, f"{experiment_name}_{self.timestamp}")
        os.makedirs(self.log_dir, exist_ok=True)
        self.run_metadata = {}
        self.generation_logs = []
        self.entropy_entries = []

    def log_metadata(self, **kwargs):
        self.run_metadata.update(kwargs)

    def log_generation(self, generation, best_fitness, avg_fitness, best_alerts,
                       best_packets, ttl_avg, payload_avg, window_avg, delay_avg):
        self.generation_logs.append({
            "generation": generation,
            "best_fitness": best_fitness,
            "avg_fitness": avg_fitness,
            "best_alerts": best_alerts,
            "best_packets": best_packets,
            "ttl_avg": ttl_avg,
            "payload_avg": payload_avg,
            "window_avg": window_avg,
            "delay_avg": delay_avg
        })

    def log_entropy(self, generation, individual_index, fitness, flag_entropy, entropy_bonus, flag_penalty, flags):
        entry = {
            "generation": generation,
            "individual_index": individual_index,
            "fitness": round(fitness, 4),
            "flag_entropy": round(flag_entropy, 4),
            "entropy_bonus": round(entropy_bonus, 4),
            "flag_penalty": round(flag_penalty, 4),
            "flags": flags
        }
        self.entropy_entries.append(entry)

    def save_individual(self, individual, generation):
        filename = os.path.join(self.log_dir, f"stealthy_individual_gen{generation}.txt")
        with open(filename, "w") as f:
            for instr in individual.instructions:
                f.write(f"{instr}\n")

    def export_logs(self):
        summary_path = os.path.join(self.log_dir, "run_summary.json")
        with open(summary_path, "w") as f:
            json.dump({
                "metadata": self.run_metadata,
                "generations": self.generation_logs
            }, f, indent=2)

        entropy_path = os.path.join(self.log_dir, "entropy.log")
        with open(entropy_path, "w") as f:
            for entry in self.entropy_entries:
                f.write(json.dumps(entry) + "\n")