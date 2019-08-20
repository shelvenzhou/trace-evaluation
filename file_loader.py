import csv
import json
from collections import defaultdict

from transaction_trace.analysis.results import AttackCandidateExporter

from result_filter import ResultFilter


def call_injection_ct_extractor(candidates, filtered, candidate):
    for attack in candidate.details["attacks"]:
        target = attack["entry_edge"][1].split(":")[1]
        candidates[target].append(candidate)


def reentrancy_ct_extractor(candidates, filtered, candidate):
    for attack in candidate.details["attacks"]:
        target = attack["entry"].split(":")[1]
        candidates[target].append(candidate)


def integer_overflow_ct_extractor(candidates, filtered, candidate):
    for attack in candidate.details["attacks"]:
        target = attack["edge"][1].split(":")[1]
        candidates[target].append(candidate)


def airdrop_hunting_ct_extractor(candidates, filtered, candidate):
    if len(candidate.results) == 0:
        candidates["unknown"].append(candidate)
    else:
        for _, tokens in candidate.results.items():
            for token_transfer_event in tokens:
                token_addr = token_transfer_event.split(":")[1]
                candidates[token_addr].append(candidate)


def call_after_destruct_ct_extractor(candidates, filtered, candidate):
    destructed_contract = candidate.details["suicided_contract"]
    candidates[destructed_contract].append(candidate)


def honeypot_ct_extractor(candidates, filtered, candidate):
    contract = candidate.details["contract"]
    if ResultFilter.honeypot_filter(candidate):
        filtered[contract].append(candidate)
    else:
        candidates[contract].append(candidate)


ct_extractors = {
    "call-injection": call_injection_ct_extractor,
    "reentrancy": reentrancy_ct_extractor,
    "integer-overflow": integer_overflow_ct_extractor,
    "airdrop-hunting": airdrop_hunting_ct_extractor,
    "call-after-destruct": call_after_destruct_ct_extractor,
    "honeypot": honeypot_ct_extractor,
}


def general_key_extractor(candidate):
    return candidate.details["transaction"]


def honeypot_key_extractor(candidate):
    return candidate.details["contract"]


key_extractors = {
    "call-injection": general_key_extractor,
    "reentrancy": general_key_extractor,
    "integer-overflow": general_key_extractor,
    "airdrop-hunting": general_key_extractor,
    "call-after-destruct": general_key_extractor,
    "honeypot": honeypot_key_extractor,
}


class FileLoader:

    @staticmethod
    def load_json(filepath):
        with open(filepath, "r") as f:
            return json.load(f)

    @staticmethod
    def load_contracts_with_defense(filepath):
        """
        ct -> contract_creation_time
        """
        contracts = dict()
        with open(filepath, "r") as f:
            r = csv.reader(f)
            for row in r:
                contracts[row[0]] = row[1]

        return contracts

    @staticmethod
    def load_attack_candidates(filepath):
        """
        attack_type -> ct -> attacks
        """
        with open(filepath, "r") as f:
            raw_data = AttackCandidateExporter.load_candidates(f)

        candidates = defaultdict(lambda: defaultdict(list))
        filtered = defaultdict(lambda: defaultdict(list))
        for cand in raw_data:
            ct_extractors[cand.type](candidates[cand.type], filtered[cand.type], cand)
        return candidates, filtered

    @staticmethod
    def load_raw_attack_candidates(filepath):
        """
        tx/ct -> attack
        """
        with open(filepath, "r") as f:
            raw_data = AttackCandidateExporter.load_candidates(f)

        candidates = dict()
        for cand in raw_data:
            candidates[key_extractors[cand.type](cand)] = cand
        return candidates
