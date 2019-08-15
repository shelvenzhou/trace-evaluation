import csv
from collections import defaultdict

from IPython import embed

from file_loader import FileLoader
from related_works import RelatedWorks
from result_filter import ResultFilter

if __name__ == "__main__":
    w = RelatedWorks()

    open_source = set()
    with open("res/defense_contracts/contracts_with_source.csv", "r") as f:
        r = csv.reader(f)
        for row in r:
            open_source.add(row[0])

    confirmed_attacks, filtered_confirmed_attacks = FileLoader.load_attack_candidates(
        "res/results/attack-candidates-20190807.log")
    failed_attacks, filtered_failed_attacks = FileLoader.load_attack_candidates(
        "res/results/failed-attacks-20190807.log")

    profited_honeypots = set()
    for addr, hs in confirmed_attacks["honeypot"].items():
        for h in hs:
            if h.details["status"] != "INITIALIZED":
                profited_honeypots.add(addr)

    defended_attacks_with_source = defaultdict(list)
    defended_attack_types = defaultdict(list)
    for attack_type in failed_attacks:
        for addr in failed_attacks[attack_type]:
            for attack in failed_attacks[attack_type][addr]:
                if addr in open_source \
                    and ("Reverted" in attack.details["failed_reason"]
                         or ("unrealized token transfer" in attack.details["failed_reason"] and len(attack.results) == 0)):
                    defended_attacks_with_source[addr].append(attack)
                    defended_attack_types[attack_type].append(attack)

    embed()
