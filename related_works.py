import json
import os
from collections import defaultdict

from config import Config
from vulnerability_type import (VT_AH, VT_CAD, VT_CI, VT_HP, VT_IO, VT_RE,
                                vulnerability_mapping)


class Dataset:

    def __init__(self, related_work):
        self.name = related_work
        self.data_filepath = os.path.join(Config.related_work_result_dir, related_work + "-results.json")

        self.vulnerability_mapping = vulnerability_mapping[related_work]

        with open(self.data_filepath, "rb") as f:
            raw_data = json.load(f)

        self.all_vulnerable_contracts = set()
        self.typed_vulnerable_contracts = defaultdict(set)
        self.contract_vulnerability = defaultdict(set)

        for addr, vuls in raw_data.items():
            self.all_vulnerable_contracts.add(addr)

            for vul in vuls:
                v = self.vulnerability_mapping.get(vul, None)

                if v is None:  # unconcerned vulnerability type
                    continue

                self.typed_vulnerable_contracts[v].add(addr)
                self.contract_vulnerability[addr].add(v)


class RelatedWorks:

    def __init__(self):
        self.works = [
            "HoneyBadger",
            "Oyente",
            "Securify",
            "Vandal",
            "ZEUS",
            "teEther",
        ]

        self.datasets = dict()
        for w in self.works:
            self.datasets[w] = Dataset(w)

    @property
    def honey_badger(self):
        return self.datasets["HoneyBadger"]

    @property
    def oyente(self):
        return self.datasets["Oyente"]

    @property
    def securify(self):
        return self.datasets["Securify"]

    @property
    def vandal(self):
        return self.datasets["Vandal"]

    @property
    def zeus(self):
        return self.datasets["ZEUS"]
