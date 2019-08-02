from config import Config
from vulnerability_type import vulnerability_mapping
from related_works import RelatedWorks

from transaction_trace.local import ContractCode, EthereumDatabase
from transaction_trace.analysis.results import AttackCandidateExporter, AttackCandidate
from transaction_trace.basic_utils import DatetimeUtils

import pickle
import json
from collections import defaultdict
from datetime import datetime
from web3 import Web3


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
        self.integer_overflow_contracts = None
        self.integer_overflow_cve = None

        self.parity_wallet = set()
        self.honeypot_profit_txs = defaultdict(list)
        self.attack_candidates = None
        self.failed_candidates = None

        self.token_loss = None
        self.reen_eth_loss = None

        self.cad = AbnormalData()
        self.attack_data = AbnormalData()
        self.failed_data = AbnormalData()

        self.confirmed_vuls = defaultdict(set)

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

        with open('res/case-study/integer-overflow-contracts.json', 'rb') as f:
            self.integer_overflow_contracts = json.load(f)

        with open('res/case-study/integer-overflow-cvelist.json', 'rb') as f:
            self.integer_overflow_cve = json.load(f)

        with open('/home/xiangjie/logs/pickles/contract_cache', 'rb') as f:
            o = pickle.load(f)
            self.contract_cache = o['contract_cache']
            self.source_code_cache = o['source_code_cache']

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
            return

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
            self.attack_candidates, self.attack_data, succeed_threshold, True, True)
        self.extract_abnormal_data(
            self.failed_candidates, self.failed_data, failed_threshold)

    def extract_abnormal_data(self, candidates, abnormal_data, threshold, cad=False, loss=False):
        token_loss = defaultdict(int)
        eth_lost = defaultdict(int)
        for cand in candidates:
            v = cand.type
            details = cand.details
            results = cand.results

            if v == 'honeypot':
                continue
            tx_hash = details['transaction'] if v != 'honeypot' else details['profit_txs'][0]
            targets = []
            air_move_targets = []
            if v == 'airdrop-hunting' and details['hunting_time'] > threshold.hunting_time:
                for node in results:
                    for result_type in results[node]:
                        if result_type.split(':')[0] == 'TOKEN_TRANSFER_EVENT':
                            token = result_type.split(':')[-1]
                            token_loss[v] += results[node][result_type]
                            if details['slave_number'] == details['hunting_time']:
                                air_move_targets.append(token)
                            else:
                                targets.append(token)
            elif v == 'call-injection':
                for attack in details['attacks']:
                    targets.append(attack['entry_edge'][1].split(':')[1])
            elif v == 'honeypot':
                targets.append(details['contract'])
                self.honeypot_profit_txs[details['contract']
                                         ] = details['profit_txs']
            elif v == 'integer-overflow':
                for node in results:
                    for result_type in results[node]:
                        if result_type.split(':')[0] == 'TOKEN_TRANSFER_EVENT':
                            token = result_type.split(':')[-1]
                            token_loss[v] += results[node][result_type]
                            if token in self.integer_overflow_contracts['candidates']:
                                targets.append(token)
            elif v == 'reentrancy':
                for intention in details['attacks']:
                    if intention['iter_num'] > threshold.iter_num:
                        cycle = intention['cycle']
                        addrs = tuple(sorted(cycle))
                        if addrs not in self.reen_addrs2target:
                            print(tx_hash, addrs)
                            continue
                        targets.append(self.reen_addrs2target[addrs])
                    eth = 0
                    for node in results:
                        for result_type in results[node]:
                            if result_type == 'ETHER_TRANSFER':
                                if results[node][result_type] > eth:
                                    eth = results[node][result_type]
                    eth_lost[targets[0]] += Web3.fromWei(eth, 'ether')
            elif v == 'call-after-destruct-checker' and cad:
                suicided_contract = details['suicided_contract']
                self.cad.vul2txs[v].add(tx_hash)
                self.cad.vul2contrs[v].add(suicided_contract)

            if len(air_move_targets) > 0:
                self.attack_data.vul2txs[v].add(tx_hash)
                for target in air_move_targets:
                    self.attack_data.vul2contrs[v].add(target)
                    if target not in self.attack_data.contr2txs[v]:
                        self.attack_data.contr2txs[v][target] = set()
                    self.attack_data.contr2txs[v][target].add(tx_hash)
                    if self.open_source_contract(target):
                        self.attack_data.vul2contrs_open_sourced[v].add(target)
            if len(targets) == 0:
                continue
            abnormal_data.vul2txs[v].add(tx_hash)
            for target in targets:
                abnormal_data.vul2contrs[v].add(target)
                if target not in abnormal_data.contr2txs[v]:
                    abnormal_data.contr2txs[v][target] = set()
                abnormal_data.contr2txs[v][target].add(tx_hash)
                if self.open_source_contract(target):
                    abnormal_data.vul2contrs_open_sourced[v].add(target)

        if loss:
            self.token_loss = token_loss
            self.reen_eth_loss = eth_lost

    def replace_honey_pot(self, abnormal_data, honeypot_log_path):
        abnormal_data.vul2txs['honeypot'].clear()
        abnormal_data.vul2contrs['honeypot'].clear()
        abnormal_data.contr2txs['honeypot'].clear()
        abnormal_data.vul2contrs_open_sourced['honeypot'].clear()

        eth_loss = 0
        with open(honeypot_log_path, 'rb') as f:
            candidates = AttackCandidateExporter.load_candidates(f)
        for cand in candidates:
            v = cand.type
            details = cand.details
            results = cand.results
            targets = []

            if v == 'honeypot' and len(details['profit_txs']) > 0:
                tx_hash = details['profit_txs'][0]
                targets.append(details['contract'])
                self.honeypot_profit_txs[details['contract']
                                         ] = details['profit_txs']
                eth_loss += Web3.fromWei(results['profits'], 'ether')
            if len(targets) == 0:
                continue
            abnormal_data.vul2txs[v].add(tx_hash)
            for target in targets:
                abnormal_data.vul2contrs[v].add(target)
                if target not in abnormal_data.contr2txs[v]:
                    abnormal_data.contr2txs[v][target] = set()
                abnormal_data.contr2txs[v][target].add(tx_hash)
                if self.open_source_contract(target):
                    abnormal_data.vul2contrs_open_sourced[v].add(target)
        return eth_loss

    def replace_reentrancy(self, abnormal_data, reen_log_path):
        abnormal_data.vul2txs['reentrancy'].clear()
        abnormal_data.vul2contrs['reentrancy'].clear()
        abnormal_data.contr2txs['reentrancy'].clear()
        abnormal_data.vul2contrs_open_sourced['reentrancy'].clear()

        eth_lost = defaultdict(int)
        with open(reen_log_path, 'rb') as f:
            candidates = AttackCandidateExporter.load_candidates(f)
        for cand in candidates:
            v = cand.type
            details = cand.details
            results = cand.results
            if v == 'honeypot':
                continue
            tx_hash = details['transaction'] if v != 'honeypot' else details['profit_txs'][0]
            targets = []
            if v == 'reentrancy':
                for intention in details['attacks']:
                    cycle = intention['cycle']
                    addrs = tuple(sorted(cycle))
                    if addrs not in self.reen_addrs2target:
                        print(tx_hash, addrs)
                        continue
                    targets.append(self.reen_addrs2target[addrs])
                eth = 0
                for node in results:
                    for result_type in results[node]:
                        if result_type == 'ETHER_TRANSFER':
                            if results[node][result_type] > eth:
                                eth = results[node][result_type]
                eth_lost[targets[0]] += Web3.fromWei(eth, 'ether')
            if len(targets) == 0:
                continue
            abnormal_data.vul2txs[v].add(tx_hash)
            for target in targets:
                abnormal_data.vul2contrs[v].add(target)
                if target not in abnormal_data.contr2txs[v]:
                    abnormal_data.contr2txs[v][target] = set()
                abnormal_data.contr2txs[v][target].add(tx_hash)
                if self.open_source_contract(target):
                    abnormal_data.vul2contrs_open_sourced[v].add(target)
        return eth_lost

    def replace_call_injection_data(self, abnormal_data):
        abnormal_data.vul2txs['call-injection'].clear()
        abnormal_data.vul2contrs['call-injection'].clear()
        abnormal_data.contr2txs['call-injection'].clear()
        abnormal_data.vul2contrs_open_sourced['call-injection'].clear()

        with open(Config.CI_LOG_FILE, 'r') as f:
            lines = f.readlines()
            rows = []
            for line in lines:
                rows.append(eval(line.strip('\n')))

        for row in rows:
            tx_hash = row['tx_hash']
            abnormal_data.vul2txs['call-injection'].add(tx_hash)
            abnormal_data.vul2contrs['call-injection'].add(row['entry'])
            if row['entry'] not in abnormal_data.contr2txs['call-injection']:
                abnormal_data.contr2txs['call-injection'][row['entry']] = set()
            abnormal_data.contr2txs['call-injection'][row['entry']
                                                      ].add(tx_hash)
            if self.open_source_contract(row['entry']):
                abnormal_data.vul2contrs_open_sourced['call-injection'].add(
                    row['entry'])
            if 'initWallet(address[],uint256,uint256)' in row['behavior']:
                self.parity_wallet.add(row['entry'])
                self.confirmed_vuls['call-injection'].add(row['entry'])

        self.confirmed_vuls['reentrancy'] = self.attack_data.vul2contrs_open_sourced['reentrancy'].copy()

        self.confirmed_vuls['integer-overflow'] = self.integer_overflow_contracts['confirmed']

        self.confirmed_vuls['airdrop-hunting'] = self.attack_data.vul2contrs_open_sourced['airdrop-hunting'].copy()


    def cmp_related_works_wo_vuls(self):
        our_candidates = set()
        related_works_candidates = set()
        reported = defaultdict(set)
        not_reported = defaultdict(set)

        for w in self.related_works.datasets:
            dataset = self.related_works.datasets[w]
            for c in dataset.all_vulnerable_contracts:
                related_works_candidates.add(c)

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

        return our_candidates, related_works_candidates, reported, not_reported

    def introduction_data(self):
        attempted_txs = set()
        succeed_txs = set()
        for v in self.attack_data.contr2txs:
            for c in self.attack_data.contr2txs[v]:
                conf = False
                if c in self.confirmed_vuls[v]:
                    conf = True
                for tx in self.attack_data.contr2txs[v][c]:
                    if conf:
                        succeed_txs.add(tx)
                    attempted_txs.add(tx)

        for v in self.failed_data.vul2txs:
            for tx in self.failed_data.vul2txs[v]:
                attempted_txs.add(tx)
        print("attemped txs: {}".format(len(attempted_txs)))
        print("succeed txs: {}".format(len(succeed_txs)))

        incident_txs = set()
        incident_contracts = set()
        incident_contracts.add('0xd2e16a20dd7b1ae54fb0312209784478d069c7b0')
        incident_contracts.add('0xf91546835f756da0c10cfa0cda95b15577b84aa7')
        for c in self.parity_wallet:
            incident_contracts.add(c)
        for v in self.attack_data.contr2txs:
            for c in self.attack_data.contr2txs[v]:
                if c in incident_contracts:
                    for tx in self.attack_data.contr2txs[v][c]:
                        incident_txs.add(tx)
        print("excluding {} of these famous incidents".format(
            len(incident_txs)/len(succeed_txs)))

        our_candidates, related_works_candidates, reported, not_reported = self.cmp_related_works_wo_vuls()
        reported_contracts = set()
        for w in reported:
            for c in reported[w]:
                if c not in incident_contracts:
                    reported_contracts.add(c)
        reported_txs = set()
        cve_txs = set()
        for v in self.attack_data.contr2txs:
            for c in self.attack_data.contr2txs[v]:
                if c in reported_contracts and c in self.confirmed_vuls[v]:
                    for tx in self.attack_data.contr2txs[v][c]:
                        reported_txs.add(tx)
                if c in self.integer_overflow_cve and c not in related_works_candidates:
                    for tx in self.attack_data.contr2txs[v][c]:
                        cve_txs.add(tx)
        print("only {} of confirmed ... are targeting".format(
            len(reported_txs)/len(succeed_txs)))
        print("{} vulnerabilities reported".format(len(reported_contracts)))
        print("{} is targeting {} vulnerabilities ... CVE database".format(
            len(cve_txs)/len(succeed_txs), len(self.integer_overflow_cve)))

        unknown_vuls = set()
        unknown_txs = set()
        for v in self.attack_data.vul2contrs:
            for c in self.attack_data.vul2contrs[v]:
                if c not in incident_contracts and c not in self.integer_overflow_cve and c not in related_works_candidates and c in self.confirmed_vuls[v]:
                    unknown_vuls.add(c)
        for v in self.attack_data.contr2txs:
            for c in self.attack_data.contr2txs[v]:
                if c in unknown_vuls:
                    for tx in self.attack_data.contr2txs[v][c]:
                        unknown_txs.add(tx)
        print("{} is actually targeting {} previously-unknown".format(len(unknown_txs)/len(succeed_txs), len(unknown_vuls)))

        confirmed_airdrop_txs = set()
        for c in self.attack_data.contr2txs['airdrop-hunting']:
            if c in self.confirmed_vuls['airdrop-hunting']:
                for tx in self.attack_data.contr2txs['airdrop-hunting'][c]:
                    confirmed_airdrop_txs.add(tx)
        print("{} of ... targeting {} ... using new attack tactics".format(
            len(confirmed_airdrop_txs)/len(succeed_txs),
            len(self.confirmed_vuls['airdrop-hunting'])))

        missed_vuls = set()
        missed_txs = set()
        for v in self.attack_data.vul2contrs:
            for c in self.attack_data.vul2contrs[v]:
                if c in self.confirmed_vuls[v] and c not in related_works_candidates:
                    missed_vuls.add(c)
        for v in self.attack_data.contr2txs:
            for c in self.attack_data.contr2txs[v]:
                if c in self.confirmed_vuls[v] and c in missed_vuls:
                    for tx in self.attack_data.contr2txs[v][c]:
                        missed_txs.add(tx)
        print("{} of confirmed adversarial  transactions  are  targeting  {}  vulnerabilities".format(len(missed_txs)/len(succeed_txs), len(missed_vuls)))

        # txs = set()
        # for v in self.attack_data.vul2txs:
        #     for tx in self.attack_data.vul2txs[v]:
        #         txs.add(tx)
        # for v in self.failed_data.vul2txs:
        #     for tx in self.failed_data.vul2txs[v]:
        #         txs.add(tx)
        # tx_time = dict()
        # db = EthereumDatabase('/mnt/data/bigquery/ethereum_transactions', 'transactions')
        # for con in db.get_all_connnections():
        #     print(con)
        #     for row in con.read('transactions', '*'):
        #         tx_hash = row['hash']
        #         if tx_hash in txs:
        #             tx_time[tx_hash] = row['block_timestamp']

        # attemp_txs = set()
        # confirm_txs = set()
        # for v in ('reentrancy', 'call-injection'):
        #     for tx in self.attack_data.vul2txs[v]:
        #         if tx_time[tx] > datetime(2015, 8, 1, 0, 0) and tx_time[tx] < datetime(2017, 8, 1, 0, 0):
        #             attemp_txs.add(tx)
        #             if tx in succeed_txs:
        #                 confirm_txs.add(tx)
        #     for tx in self.failed_data.vul2txs[v]:
        #         if tx_time[tx] > datetime(2015, 8, 1, 0, 0) and tx_time[tx] < datetime(2017, 8, 1, 0, 0):
        #             attemp_txs.add(tx)

        # print("{} attemped, {} confirmed between 2015.8 and 2017.8".format(len(attemp_txs)/len(attempted_txs), len(confirm_txs)/len(succeed_txs)))

        # attemp_txs = set()
        # confirm_txs = set()
        # for v in ('airdrop-hunting', 'integer-overflow'):
        #     for tx in self.attack_data.vul2txs[v]:
        #         if tx_time[tx] > datetime(2017, 9, 1, 0, 0) and tx_time[tx] < datetime(2019, 3, 1, 0, 0):
        #             attemp_txs.add(tx)
        #             if tx in succeed_txs:
        #                 confirm_txs.add(tx)
        #     for tx in self.failed_data.vul2txs[v]:
        #         if tx_time[tx] > datetime(2017, 9, 1, 0, 0) and tx_time[tx] < datetime(2019, 3, 1, 0, 0):
        #             attemp_txs.add(tx)
        # print("{} attemped, {} confirmed between 2017.9 and 2019.3".format(len(attemp_txs)/len(attempted_txs), len(confirm_txs)/len(succeed_txs)))
