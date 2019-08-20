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

    # confirmed_attacks = FileLoader.load_raw_attack_candidates("res/results/attack-candidates-20190813.log")
    # failed_attacks = FileLoader.load_raw_attack_candidates("res/results/failed-attacks-20190813.log")
    # confirmed_honeypots = set()
    # with open("res/results/confirmed_honeypot.csv", "r") as f:
    #     r = csv.reader(f)
    #     for row in r:
    #         confirmed_honeypots.add(row[0])
    # # dict_keys(['call-injection', 'reentrancy', 'integer-overflow', 'airdrop-hunting'])
    # confirmed_others = FileLoader.load_json("res/results/confirmed_txs.json")
    # confirmed_cad = FileLoader.load_json("res/results/cad_txs.json")

    # all_results = list()
    # for honeypot in confirmed_honeypots:
    #     all_results.append(confirmed_attacks[honeypot])
    # for cad in confirmed_cad:
    #     all_results.append(confirmed_attacks[cad])
    # for vul_type in confirmed_others:
    #     for tx in confirmed_others[vul_type]:
    #         if tx in confirmed_attacks:
    #             all_results.append(confirmed_attacks[tx])

    confirmed_attacks, _ = FileLoader.load_attack_candidates("./all_results.json")
    failed_attacks, _ = FileLoader.load_attack_candidates("res/results/failed-attacks-20190813.log")
    defended_attack_types = defaultdict(set)
    for attack_type in failed_attacks:
        for addr in failed_attacks[attack_type]:
            for attack in failed_attacks[attack_type][addr]:
                # if addr in open_source \
                #     and ("Reverted" in attack.details["failed_reason"]
                #          or ("unrealized token transfer" in attack.details["failed_reason"] and len(attack.results) == 0)):
                defended_attack_types[attack_type].add(addr)

    confirmed_attack_types = defaultdict(lambda: defaultdict(int))
    for attack_type in confirmed_attacks:
        for addr in confirmed_attacks[attack_type]:
            for attack in confirmed_attacks[attack_type][addr]:
                # if addr in open_source \
                #     and ("Reverted" in attack.details["failed_reason"]
                #          or ("unrealized token transfer" in attack.details["failed_reason"] and len(attack.results) == 0)):
                confirmed_attack_types[attack_type][addr] += 1


    defenses = dict()
    defenses["candistr"] = FileLoader.load_contracts_with_defense("res/defense_contracts/defense_candistr.csv")
    defenses["extcodesize"] = FileLoader.load_contracts_with_defense("res/defense_contracts/defense_extcodesize.csv")
    defenses["nonreentrant"] = FileLoader.load_contracts_with_defense("res/defense_contracts/defense_nonreentrant.csv")
    defenses["onlyowner"] = FileLoader.load_contracts_with_defense("res/defense_contracts/defense_onlyowner.csv")
    defenses["onlyproxy"] = FileLoader.load_contracts_with_defense("res/defense_contracts/defense_onlyproxy.csv")
    defenses["safemath"] = FileLoader.load_contracts_with_defense("res/defense_contracts/defense_safemath.csv")
    defenses["txorigin"] = FileLoader.load_contracts_with_defense("res/defense_contracts/defense_tx_origin.csv")

    embed()
