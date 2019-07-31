from config import Config
from vulnerability_type import vulnerability_mapping
from related_works import RelatedWorks

from transaction_trace.local import ContractCode
from transaction_trace.analysis.results import AttackCandidateExporter, AttackCandidate
from transaction_trace.basic_utils import DatetimeUtils

import pickle
from collections import defaultdict


class AbnormalData(object):
    def __init__(self):
        self.vul2txs = defaultdict(set)
        self.vul2contrs = defaultdict(set)
        self.contr2txs = defaultdict(dict)
        self.vul2contrs_open_sourced = defaultdict(set)


class Thresholds(object):
    def __init__(self, hunting_time, iter_num):
        self.hunting_time = hunting_time
        self.iter_num = iter_num


class EvalUtil(object):
    def __init__(self, attack_log_path, failed_attack_log_path, db_passwd):
        self.contract_code_db = ContractCode(passwd=db_passwd)
        self.related_works = RelatedWorks()
        self.attack_log_path = attack_log_path
        self.failed_attack_log_path = failed_attack_log_path

        self.contract_cache = dict()
        self.source_code_cache = dict()
        self.reen_addrs2target = None
        self.create_time = None

        self.honeypot_profit_txs = defaultdict(list)
        self.attack_candidates = None
        self.failed_candidates = None

        self.attack_data = AbnormalData()
        self.failed_data = AbnormalData()

        self.load_data()

    def load_data(self):
        with open(Config.REENTRANCY_ADDRS_MAP, 'rb') as f:
            self.reen_addrs2target = pickle.load(f)

        with open(Config.CONTRACT_CREATE_TIME, 'rb') as f:
            self.create_time = pickle.load(f)

        with open(self.attack_log_path, 'rb') as f:
            self.attack_candidates = AttackCandidateExporter.load_candidates(f)

        with open(self.failed_attack_log_path, 'rb') as f:
            self.failed_candidates = AttackCandidateExporter.load_candidates(f)

    def open_source_contract(self, address):
        self.read_contract_info(address)
        if self.contract_cache[address]:
            bytecode_hash = self.contract_cache[address]['bytecode_hash']
            if self.source_code_cache[bytecode_hash] and self.source_code_cache[bytecode_hash]['source_code'] != '':
                return True
        return False

    def read_contract_info(self, address):
        if address in self.contract_cache:
            return
        row = self.contract_code_db.read(
            'byte_code', '*', "WHERE address = %s", (address,)).fetchone()
        if row:
            self.contract_cache[address] = {
                'bytecode_hash': row[2],
                'is_erc20': row[4],
                'block_timestamp': row[6],
                'block_hash': row[8],
            }
        else:
            self.contract_cache[address] = None

        bytecode_hash = self.contract_cache[address]['bytecode_hash']
        if bytecode_hash in self.source_code_cache:
            return
        row = self.contract_code_db.read(
            'source_code', '*', "WHERE bytecode_hash = %s", (bytecode_hash,)).fetchone()
        if row:
            self.source_code_cache[bytecode_hash] = {
                'source_code': row[1],
                'contract_name': row[3]
            }
        else:
            self.source_code_cache[bytecode_hash] = None

    def extract_data(self, succeed_threshold, failed_threshold):
        self.extract_abnormal_data(
            self.attack_candidates, self.attack_data, succeed_threshold)
        self.extract_abnormal_data(
            self.failed_candidates, self.failed_data, failed_threshold)

    def extract_abnormal_data(self, candidates, data, threshold):
        abnormal_data = AbnormalData()
        for cand in candidates:
            v = cand.type
            details = cand.details
            results = cand.results

            tx_hash = details['transaction'] if v != 'honeypot' else details['profit_txs'][0]
            target = None
            if v == 'airdrop-hunting' and details['hunting_time'] > threshold.hunting_time:
                for node in results:
                    for result_type in results[node]:
                        if result_type.split(':')[0] == 'TOKEN_TRANSFER_EVENT':
                            target = result_type.split(':')[-1]
            elif v == 'call-after-destruct-checker':
                target = details['suicided_contract']
            elif v == 'call-injection':
                target = details['entry_edge'][1].split(':')[1]
            elif v == 'honeypot':
                target = details['contract']
                self.honeypot_profit_txs[target] = details['profit_txs']
            elif v == 'integer-overflow':
                for node in results:
                    for result_type in results[node]:
                        if result_type.split(':')[0] == 'TOKEN_TRANSFER_EVENT':
                            target = result_type.split(':')[-1]
            elif v == 'reentrancy':
                for intention in details['attacks']:
                    if intention['iter_num'] > threshold.iter_num:
                        cycle = intention['cycle']
                        addrs = tuple(sorted(cycle))
                        if addrs not in self.reen_addrs2target:
                            continue
                        target = self.reen_addrs2target[addrs]

            if target == None:
                continue
            abnormal_data.vul2txs[v].add(tx_hash)
            abnormal_data.vul2contrs[v].add(target)
            if target not in abnormal_data.contr2txs[v]:
                abnormal_data.contr2txs[v][target] = set()
            abnormal_data.contr2txs[v][target].add(tx_hash)
            if self.open_source_contract(target):
                abnormal_data.vul2contrs_open_sourced[v].add(target)

        data = abnormal_data

    def cmp_related_works_wo_vuls(self):
        our_candidates = set()
        reported = defaultdict(set)
        not_reported = defaultdict(set)

        for v in self.attack_data.vul2contrs:
            for c in self.attack_data.vul2contrs[v]:
                our_candidates.add(c)
        for c in our_candidates:
            for w in self.related_works.datasets:
                dataset = self.related_works.datasets[w]
                if c in dataset.all_vulnerable_contracts:
                    reported[w].add(c)
                elif c in self.create_time and DatetimeUtils.time_to_str(self.create_time[c]) <= Config.dataset_latest_time[w]:
                    not_reported[w].add(c)

        return our_candidates, reported, not_reported
