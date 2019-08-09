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

    confirmed_attacks = FileLoader.load_attack_candidates("res/results/attack-candidates-20190807.log")
    filtered_honeypot = ResultFilter.filter_honeypot_results(confirmed_attacks["honeypot"])

    failed_attacks = FileLoader.load_attack_candidates("res/results/failed-attacks-20190807.log")

    embed()
