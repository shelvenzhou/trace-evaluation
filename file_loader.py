import csv
import json

from transaction_trace.analysis.results import AttackCandidateExporter


class FileLoader:

    @staticmethod
    def load_json(filepath):
        with open(filepath, "r") as f:
            return json.load(f)

    @staticmethod
    def load_contracts_with_defense(filepath):
        contracts = dict()
        with open(filepath, "r") as f:
            r = csv.reader(f)
            for row in r:
                contracts[row[0]] = row[1]

        return contracts

    @staticmethod
    def load_attack_candidates(filepath):
        with open(filepath, "r") as f:
            return AttackCandidateExporter.load_candidates(f)
