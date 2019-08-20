import csv
import os
from collections import defaultdict

from IPython import embed
from transaction_trace.analysis.results import AttackCandidateExporter

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

    # unprofit_honeypots = set()
    # with open("res/case-study/unprofited_honeypots.csv", "r") as f:
    #     r = csv.reader(f)
    #     for row in r:
    #         unprofit_honeypots.add(row[0])
    leaked_honeypots = set()
    with open("res/case-study/leaked_honeypots.csv", "r") as f:
        r = csv.reader(f)
        for row in r:
            leaked_honeypots.add(row[0])

    # wallet_contracts = set()
    # with open("res/defense_contracts/wallet_contracts.csv", "r") as f:
    #     r = csv.reader(f)
    #     for row in r:
    #         wallet_contracts.add(row[0])
    # forwarder_contracts = set()
    # with open("res/defense_contracts/forwarder_contracts.csv", "r") as f:
    #     r = csv.reader(f)
    #     for row in r:
    #         forwarder_contracts.add(row[0])

    confirmed_honeypots = set()
    with open("res/results/confirmed_honeypot.csv", "r") as f:
        r = csv.reader(f)
        for row in r:
            confirmed_honeypots.add(row[0])

    confirmed_attacks, filtered_attacks = FileLoader.load_attack_candidates(
        "res/results/honeypot-20190812.log")
    honeypots = dict()
    for addr, hs in confirmed_attacks["honeypot"].items():
        for h in hs:
            addr = h.details["contract"]
            if addr in open_source:
                honeypots[addr] = h

    ours = set(honeypots.keys())
    theirs = w.honey_badger.all_vulnerable_contracts

    # out_honeypot = open("confirmed_honeypots.log", "w+")
    # honeypot_file = AttackCandidateExporter(out_honeypot)

    # for addr in confirmed_honeypots:
    #     honeypot_file.dump_candidate(honeypots[addr])
    # for addr in ours.intersection(theirs):
    #     honeypot_file.dump_candidate(honeypots[addr])

    embed()
