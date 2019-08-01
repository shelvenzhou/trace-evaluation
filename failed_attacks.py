from transaction_trace.analysis.results import AttackCandidateExporter
from related_works import RelatedWorks
from collections import defaultdict
from IPython import embed

if __name__ == "__main__":
    w = RelatedWorks()

    with open("res/results/failed-attacks-20190730.log", "r") as f:
        raw_data = AttackCandidateExporter.load_candidates(f)

    failed_attacks = defaultdict(list)
    for attack in raw_data:
        failed_attacks[attack.type].append(attack)

    call_injection_targets = defaultdict(list)
    for call_injection in failed_attacks["call-injection"]:
        for attack in call_injection.details["attacks"]:
            target = attack["entry_edge"][1].split(":")[1]
            call_injection_targets[target].append(call_injection)

    integer_overflow_targets = defaultdict(list)
    for integer_overflow in failed_attacks["integer-overflow"]:
        for attack in integer_overflow.details["attacks"]:
            target = attack["edge"][1].split(":")[1]
            integer_overflow_targets[target].append(integer_overflow)

    reentrancy_targets = defaultdict(list)
    for reentrancy in failed_attacks["reentrancy"]:
        for attack in reentrancy.details["attacks"]:
            target = attack["entry"].split(":")[1]
            reentrancy_targets[target].append(reentrancy)

    airdrop_hunting_targets = defaultdict(list)
    for airdrop_hunting in failed_attacks["airdrop-hunting"]:
        if len(airdrop_hunting.results) == 0:
            airdrop_hunting_targets["unknown"].append(airdrop_hunting)
        else:
            for _, tokens in airdrop_hunting.results.items():
                for token_transfer_event in tokens:
                    token_addr = token_transfer_event.split(":")[1]
                    airdrop_hunting_targets[token_addr].append(airdrop_hunting)

    embed()
