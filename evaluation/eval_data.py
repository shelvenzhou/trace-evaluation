from transaction_trace.local import ContractCode
from transaction_trace.analysis.results import AttackCandidateExporter, AttackCandidate
from transaction_trace.local import EVMExecutor
from transaction_trace.basic_utils import DatetimeUtils

from config import Config

import pickle
import json
import csv
from collections import defaultdict
from web3 import Web3
import os
from dateutil.relativedelta import relativedelta
from IPython import embed


class AbnormalData(object):
    def __init__(self):
        self.vul2txs = defaultdict(set)
        self.vul2contrs = defaultdict(set)
        self.contr2txs = defaultdict(dict)
        self.vul2contrs_open_sourced = defaultdict(set)

class EvalData(object):
    def __init__(self, attack_log_path, failed_attack_log_path, db_passwd):
        self.contract_code_db = ContractCode(passwd=db_passwd)
        # self.contract_code_db = None
        self.evm_executor = EVMExecutor()

        self.attack_log_path = attack_log_path
        self.failed_attack_log_path = failed_attack_log_path

        self.contract_cache = dict()
        self.source_code_cache = dict()
        self.open_source_contracts = None
        self.create_time = None
        self.eth_price = None

        self.reen_cycle2target = None
        self.integer_overflow_contracts = None
        self.integer_overflow_cve = None
        self.honeypot_contracts = None
        self.defense_contracts = dict()

        self.related_works_result = None

        self.month2txs = None
        self.tx_time = dict()
        self.parity_wallet = set()

        self.attack_candidates = None
        self.failed_candidates = None

        self.attack_loss = None
        self.failed_loss = None
        self.eth_dollar_loss = None
        self.three_months_loss = {'ether': defaultdict(dict), 'token': defaultdict(dict)}

        self.attack_data = AbnormalData()
        self.failed_data = AbnormalData()

        self.confirmed_vuls = defaultdict(set)

        self.load_data()

    def dump_cache(self):
        print('dumping contract cache')
        with open('local_res/contract_cache', 'wb') as f:
            pickle.dump({'contract_cache': self.contract_cache,
                            'source_code_cache': self.source_code_cache}, f)

    def dump_bytecode(self, dump_path):
        if not os.path.exists(dump_path):
            os.makedirs(dump_path)
        for v in self.attack_data.vul2contrs:
            print('dumping {}'.format(v))
            vp = os.path.join(dump_path, v)
            if not os.path.exists(vp):
                os.makedirs(vp)
            for c in self.attack_data.vul2contrs[v]:
                cp = os.path.join(vp, "{}.hex".format(c))
                self.read_bytecode(c)
                if self.contract_cache[c] is not None:
                    bytecode = self.contract_cache[c]['bytecode'].lstrip('0x')
                    deployed_code = self.evm_executor.deployed_code(bytecode)
                    bytecode = deployed_code.lstrip('0x') if deployed_code.startswith('0x') and deployed_code != '0x' else bytecode.lstrip('0x')
                    with open(cp, 'w') as f:
                        f.write(bytecode)

    def load_data(self):
        print("loading data")

        with open(Config.CONTRACT_CREATE_TIME, 'rb') as f:
            self.create_time = pickle.load(f)

        with open(self.attack_log_path, 'rb') as f:
            self.attack_candidates = AttackCandidateExporter.load_candidates(f)

        with open(self.failed_attack_log_path, 'rb') as f:
            self.failed_candidates = AttackCandidateExporter.load_candidates(f)

        with open('res/case-study/reentrancy-cycle2target.json', 'rb') as f:
            self.reen_cycle2target = json.load(f)

        with open('res/case-study/integer-overflow-contracts.json', 'rb') as f:
            self.integer_overflow_contracts = json.load(f)

        with open('res/case-study/honeypot-contracts.json', 'rb') as f:
            self.honeypot_contracts = json.load(f)

        with open('res/case-study/integer-overflow-cvelist.json', 'rb') as f:
            self.integer_overflow_cve = json.load(f)

        with open('res/case-study/open-source-reentrancy.json', 'rb') as f:
            self.open_source_reentrancy = json.load(f)

        with open('res/case-study/related-works-result.json', 'rb') as f:
            self.related_works_result = json.load(f)

        with open('res/base-data/eth_price.json', 'rb') as f:
            self.eth_price = json.load(f)

        with open('res/defense_contracts/contracts_with_source.csv', 'r') as f:
            self.open_source_contracts = set([i[0] for i in csv.reader(f)])

        with open('res/defense_contracts/can_distr.csv', 'r') as f:
            self.defense_contracts['can_distr'] = [i[0] for i in csv.reader(f)]

        with open('res/defense_contracts/is_human.csv', 'r') as f:
            self.defense_contracts['is_human'] = [i[0] for i in csv.reader(f)]

        with open('res/defense_contracts/non_reentrant.csv', 'r') as f:
            self.defense_contracts['non_reentrant'] = [i[0] for i in csv.reader(f)]

        with open('res/defense_contracts/only_owner.csv', 'r') as f:
            self.defense_contracts['only_owner'] = [i[0] for i in csv.reader(f)]

        with open('res/defense_contracts/safemath.csv', 'r') as f:
            self.defense_contracts['safemath'] = [i[0] for i in csv.reader(f)]

        if not os.path.exists(Config.CONTRACT_CACHE_PICKLE_FILE):
            return
        with open(Config.CONTRACT_CACHE_PICKLE_FILE, 'rb') as f:
            o = pickle.load(f)
            self.contract_cache = o['contract_cache']
            self.source_code_cache = o['source_code_cache']

    def open_source_contract(self, address):
        if address in self.open_source_contracts:
            return True
        else:
            return False

        self.read_contract_info(address)
        if self.contract_cache[address]:
            bytecode_hash = self.contract_cache[address]['bytecode_hash']
            if self.source_code_cache[bytecode_hash] and self.source_code_cache[bytecode_hash]['source_code'] != '':
                return True
        return False

    def read_bytecode(self, address):
        if address in self.contract_cache:
            return
        row = self.contract_code_db.read(
            'byte_code', '*', "WHERE address = %s", (address,)).fetchone()
        if row:
            self.contract_cache[address] = {
                'bytecode': row[1],
                'bytecode_hash': row[2],
                'is_erc20': row[4],
                'block_timestamp': row[6],
                'block_hash': row[8],
            }
        else:
            self.contract_cache[address] = None
            return None

        bytecode_hash = self.contract_cache[address]['bytecode_hash']
        return bytecode_hash

    def read_source_code(self, bytecode_hash):
        if bytecode_hash is None:
            return
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

    def read_contract_info(self, address):
        bytecode_hash = self.read_bytecode(address)
        self.read_source_code(bytecode_hash)

    def time_gap_loss(self, tx_time, tx_hash, target, amount, loss_type, v, month_gap):
        time_gap = relativedelta(months=month_gap)
        if DatetimeUtils.str_to_time(tx_time) < self.create_time[target].replace(tzinfo=None) + time_gap:
            if target not in self.three_months_loss[loss_type][v]:
                self.three_months_loss[loss_type][v][target] = 0
            if loss_type == 'token':
                self.three_months_loss['token'][v][target] += amount
            elif loss_type == 'ether':
                self.three_months_loss['ether'][v][target] += amount * self.eth_price[tx_time[:10]]

    def extract_data(self, succeed_threshold, failed_threshold):
        self.extract_abnormal_data(
            self.attack_candidates, self.attack_data, succeed_threshold)
        self.extract_abnormal_data(
            self.failed_candidates, self.failed_data, failed_threshold, True)

    def extract_abnormal_data(self, candidates, abnormal_data, threshold, failed_data=False):
        eco_loss = {
            'ether': defaultdict(dict),
            'token': defaultdict(dict)
        }
        eth_dollar_loss = defaultdict(dict)

        month2txs = dict()

        for cand in candidates:
            v = cand.type
            details = cand.details
            results = cand.results

            if v == 'honeypot':
                tx_hash = details['create_tx']
                tx_time = details['create_time']
            else:
                tx_hash = details['transaction']
                tx_time = details['tx_time']
            self.tx_time[tx_hash] = tx_time

            targets = []
            if v == 'airdrop-hunting' and details['hunting_time'] > threshold.hunting_time:
                for node in results:
                    for result_type in results[node]:
                        if result_type.split(':')[0] == 'TOKEN_TRANSFER_EVENT':
                            token = result_type.split(':')[1]
                            targets.append(token)
                            if token not in eco_loss['token']['airdrop-hunting']:
                                eco_loss['token']['airdrop-hunting'][token] = 0
                            eco_loss['token']['airdrop-hunting'][token] += results[node][result_type]
                            self.time_gap_loss(tx_time, tx_hash, token, results[node][result_type], 'token', v, 3)
            elif v == 'call-injection':
                for attack in details['attacks']:
                    targets.append(attack['entry_edge'][1].split(':')[1])
            elif v == 'honeypot':
                target = details['contract']
                if target not in self.honeypot_contracts['candidates']:
                    continue
                targets.append(details['contract'])
                eth = float(Web3.fromWei(results['profits'], 'ether'))
                if target not in eco_loss['ether']['honeypot']:
                    eco_loss['ether']['honeypot'][target] = 0
                    eth_dollar_loss['honeypot'][target] = 0
                eco_loss['ether']['honeypot'][target] += eth
                eth_dollar_loss['honeypot'][target] += eth * self.eth_price[tx_time[:10]]
                self.time_gap_loss(tx_time, tx_hash, target, eth, 'ether', v, 3)
            elif v == 'integer-overflow' :
                if failed_data:
                    for attack in details['attacks']:
                        targets.append(attack['edge'][1].split(':')[1])
                else:
                    results['profits'] = results.copy()
                    for node in results['profits']:
                        for result_type in results['profits'][node]:
                            if result_type.split(':')[0] == 'TOKEN_TRANSFER_EVENT':
                                token = result_type.split(':')[1]
                                amount = results['profits'][node][result_type]
                                if token not in self.integer_overflow_contracts['candidates'] or amount <= threshold.overflow_thr:
                                    continue
                                targets.append(token)
                                if token not in eco_loss['token']['integer-overflow']:
                                    eco_loss['token']['integer-overflow'][token] = 0
                                eco_loss['token']['integer-overflow'][token] += results['profits'][node][result_type]
            elif v == 'reentrancy':
                target = None
                for intention in details['attacks']:
                    if intention['iter_num'] > threshold.iter_num:
                        cycle = intention['cycle']
                        addrs = str(tuple(sorted(cycle)))
                        if intention['iter_num'] == 1.5 and '0xd654bdd32fc99471455e86c2e7f7d7b6437e9179' not in addrs:
                            continue
                        if addrs not in self.reen_cycle2target:
                            print('reentrancy', tx_hash, addrs)
                            embed()
                        else:
                            t = self.reen_cycle2target[addrs]
                            if t == '0xc6b330df38d6ef288c953f1f2835723531073ce2':
                                continue
                            target = t
                            targets.append(target)
                if target == None:
                    continue
                eth = 0
                for node in results:
                    for result_type in results[node]:
                        rt = result_type.split(':')[0]
                        if rt == 'ETHER_TRANSFER':
                            if results[node][result_type] > eth:
                                eth = results[node][result_type]
                        elif rt == 'TOKEN_TRANSFER_EVENT':
                            token = result_type.split(':')[1]
                            if token not in eco_loss['token']['reentrancy']:
                                eco_loss['token']['reentrancy'][token] = 0
                            eco_loss['token']['reentrancy'][token] += results[node][result_type]
                if target not in eco_loss['ether']['reentrancy']:
                    eco_loss['ether']['reentrancy'][target] = 0
                    eth_dollar_loss['reentrancy'][target] = 0
                eth = float(Web3.fromWei(eth, 'ether'))
                eco_loss['ether']['reentrancy'][target] += eth
                eth_dollar_loss['reentrancy'][target] += eth * self.eth_price[tx_time[:10]]
                self.time_gap_loss(tx_time, tx_hash, target, eth, 'ether', v, 3)
            elif v == 'call-after-destruct':
                suicided_contract = details['suicided_contract']
                targets.append(suicided_contract)
                for result_type in results:
                    rt = result_type.split(':')[0]
                    if rt == 'ETHER_TRANSFER':
                        if suicided_contract not in eco_loss['ether']['call-after-destruct']:
                            eco_loss['ether']['call-after-destruct'][suicided_contract] = 0
                            eth_dollar_loss['call-after-destruct'][suicided_contract] = 0
                        eth = float(Web3.fromWei(results['ETHER_TRANSFER'], 'ether'))
                        eco_loss['ether']['call-after-destruct'][suicided_contract] += eth
                        eth_dollar_loss['call-after-destruct'][suicided_contract] += eth * self.eth_price[tx_time[:10]]
                        self.time_gap_loss(tx_time, tx_hash, suicided_contract, eth, 'ether', v, 3)
                    elif rt == 'TOKEN_TRANSFER':
                        token = result_type.split(':')[1]
                        if token not in eco_loss['token']['call-after-destruct']:
                            eco_loss['token']['call-after-destruct'][token] = 0
                        eco_loss['token']['call-after-destruct'][token] += results[result_type]

            if len(targets) == 0:
                continue
            abnormal_data.vul2txs[v].add(tx_hash)
            tx_month = tx_time[:7]
            if tx_month not in month2txs:
                month2txs[tx_month] = defaultdict(set)
            month2txs[tx_month][v].add(tx_hash)
            for target in targets:
                abnormal_data.vul2contrs[v].add(target)
                if target not in abnormal_data.contr2txs[v]:
                    abnormal_data.contr2txs[v][target] = set()
                abnormal_data.contr2txs[v][target].add(tx_hash)
                if self.open_source_contract(target):
                    abnormal_data.vul2contrs_open_sourced[v].add(target)

        if failed_data:
            self.failed_loss = eco_loss
        else:
            self.attack_loss = eco_loss
            self.eth_dollar_loss = eth_dollar_loss
            self.month2txs = month2txs

    def update_confirmed_vuls(self):
        self.confirmed_vuls = {
            'call-injection': set(self.parity_wallet),
            'reentrancy': self.attack_data.vul2contrs_open_sourced['reentrancy'],
            'call-after-destruct': self.attack_data.vul2contrs['call-after-destruct'],
            'integer-overflow': set(self.integer_overflow_contracts['confirmed']),
            'airdrop-hunting': self.attack_data.vul2contrs_open_sourced['airdrop-hunting'],
            'honeypot': set(self.honeypot_contracts['confirmed'])
        }
