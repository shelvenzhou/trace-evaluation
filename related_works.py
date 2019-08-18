from vulnerability_type import VT_AH, VT_CAD, VT_CI, VT_HP, VT_IO, VT_RE, vulnerability_mapping
from config import Config

from collections import defaultdict
import os
import subprocess
import json
import time


class RelatedWorksRunner:

    def __init__(self, eval_path):
        self.eval_path = eval_path
        self.bytecodes_path = os.path.join(eval_path, 'bytecodes')

    def run(self, cmd, name, addr=False):
        print(time.ctime(), name)
        dirs = os.listdir(self.bytecodes_path)
        outputs_dir = os.path.join(self.eval_path, name)
        if not os.path.exists(outputs_dir):
            os.mkdir(outputs_dir)
        for v in dirs:
            if v not in vulnerability_mapping[name].values():
                continue
            print("running on {}".format(v))
            vp = os.path.join(self.bytecodes_path, v)
            for bytecode_file in os.listdir(vp):
                address = bytecode_file.split('.')[0]
                target = address if addr else os.path.join(vp, bytecode_file)

                output_dir = os.path.join(outputs_dir, v)
                if not os.path.exists(output_dir):
                    os.mkdir(output_dir)
                output_file = os.path.join(output_dir, "{}".format(address))
                print(bytecode_file)
                if not os.path.exists(output_file):
                    try:
                        re = subprocess.run(cmd.format(target, output_file).split(), timeout=120, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        print(re.stdout.decode(),re.stderr.decode())
                    except subprocess.TimeoutExpired:
                        print('timeout')


    def run_mythril(self):
        cmd = "myth analyze -a {} -o json > {} --execution-timeout 120"
        self.run(cmd, 'Mythril', addr=True)

    def run_teether(self):
        cmd = "python3 /home/xiangjie/teether/bin/gen_exploit.py {} 0x1234 0x1000 +1000 {}"
        self.run(cmd, 'teEther')

    def run_securify(self):
        cmd = "java -jar /home/xiangjie/securify/build/libs/securify.jar -fh {} --livestatusfile {}"
        self.run(cmd, 'Securify')

    def run_oyente(self):
        # docker_cmd = "sudo docker run -i -t -v ~/logs/evaluation:/evaluation luongnguyen/oyente"
        cmd = "python /oyente/oyente/oyente.py -s /evaluation/bytecodes/reentrancy/{} -b > /evaluation/oyente/reentrancy/{} 2>&1"

        print(time.ctime(), 'Oyente')
        for bytecode_file in os.listdir("/evaluation/bytecodes/reentrancy"):
            targte = bytecode_file
            address = bytecode_file.strip('.hex')
            output_file = "{}.out".format(address)
            os.system(cmd.format(targte, output_file))

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
