import csv
import json
from collections import defaultdict

from transaction_trace.analysis.results import AttackCandidateExporter

from result_filter import ResultFilter


def call_injection_extractor(call_injections, filtered, call_injection):
    for attack in call_injection.details["attacks"]:
        target = attack["entry_edge"][1].split(":")[1]
        call_injections[target].append(call_injection)


def reentrancy_extractor(reentrancies, filtered, reentrancy):
    for attack in reentrancy.details["attacks"]:
        target = attack["entry"].split(":")[1]
        reentrancies[target].append(reentrancy)


def integer_overflow_extractor(integer_overflows, filtered, integer_overflow):
    for attack in integer_overflow.details["attacks"]:
        target = attack["edge"][1].split(":")[1]
        integer_overflows[target].append(integer_overflow)


def airdrop_hunting_extractor(airdrop_huntings, filtered, airdrop_hunting):
    if len(airdrop_hunting.results) == 0:
        airdrop_huntings["unknown"].append(airdrop_hunting)
    else:
        for _, tokens in airdrop_hunting.results.items():
            for token_transfer_event in tokens:
                token_addr = token_transfer_event.split(":")[1]
                airdrop_huntings[token_addr].append(airdrop_hunting)


def call_after_destruct_extractor(call_after_destructs, filtered, call_after_destruct):
    destructed_contract = call_after_destruct.details["suicided_contract"]
    call_after_destructs[destructed_contract].append(call_after_destruct)


def honeypot_extractor(honeypots, filtered, honeypot):
    contract = honeypot.details["contract"]
    if ResultFilter.honeypot_filter(honeypot):
        filtered[contract].append(honeypot)
    else:
        honeypots[contract].append(honeypot)


contract_addr_extractors = {
    "call-injection": call_injection_extractor,
    "reentrancy": reentrancy_extractor,
    "integer-overflow": integer_overflow_extractor,
    "airdrop-hunting": airdrop_hunting_extractor,
    "call-after-destruct": call_after_destruct_extractor,
    "honeypot": honeypot_extractor,
}


class FileLoader:

    @staticmethod
    def load_json(filepath):
        with open(filepath, "r") as f:
            return json.load(f)

    @staticmethod
    def load_contracts_with_defense(filepath):
        """
        contract_address -> contract_creation_time
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
        attack_type -> contract_address -> attacks
        """
        with open(filepath, "r") as f:
            raw_data = AttackCandidateExporter.load_candidates(f)

        candidates = defaultdict(lambda: defaultdict(list))
        filtered = defaultdict(lambda: defaultdict(list))
        for attack in raw_data:
            contract_addr_extractors[attack.type](candidates[attack.type], filtered[attack.type], attack)
        return candidates, filtered
