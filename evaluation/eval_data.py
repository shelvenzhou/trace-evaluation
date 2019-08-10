from transaction_trace.local import ContractCode
from transaction_trace.analysis.results import AttackCandidateExporter, AttackCandidate
from transaction_trace.local import EVMExecutor

from config import Config

import pickle
import json
from collections import defaultdict
from web3 import Web3
import os
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
        self.evm_executor = EVMExecutor()

        self.attack_log_path = attack_log_path
        self.failed_attack_log_path = failed_attack_log_path

        self.contract_cache = dict()
        self.source_code_cache = dict()
        self.create_time = None

        self.reen_cycle2target = None
        self.integer_overflow_contracts = None
        self.integer_overflow_cve = None

        self.parity_wallet = set()
        self.honeypot_profit_txs = defaultdict(list)

        self.attack_candidates = None
        self.failed_candidates = None

        self.attack_loss = None
        self.failed_loss = None

        self.cad = AbnormalData()
        self.attack_data = AbnormalData()
        self.failed_data = AbnormalData()

        self.confirmed_vuls = defaultdict(set)

        self.load_data()

    def __del__(self):
        print('dumping contract cache')
        with open('/home/xiangjie/logs/pickles/contract_cache', 'wb') as f:
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

        with open('res/case-study/integer-overflow-cvelist.json', 'rb') as f:
            self.integer_overflow_cve = json.load(f)
        with open('res/case-study/open-source-reentrancy.json', 'rb') as f:
            self.open_source_reentrancy = json.load(f)

        if not os.path.exists(Config.CONTRACT_CACHE_PICKLE_FILE):
            return
        with open(Config.CONTRACT_CACHE_PICKLE_FILE, 'rb') as f:
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
        for cand in candidates:
            v = cand.type
            details = cand.details
            results = cand.results

            if v == 'honeypot':
                continue
            tx_hash = details['transaction'] if v != 'honeypot' else details['profit_txs'][0]
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
            elif v == 'call-injection':
                for attack in details['attacks']:
                    targets.append(attack['entry_edge'][1].split(':')[1])
            elif v == 'honeypot':
                targets.append(details['contract'])
                self.honeypot_profit_txs[details['contract']
                                         ] = details['profit_txs']
            elif v == 'integer-overflow' :
                if failed_data:
                    for attack in details['attacks']:
                        targets.append(attack['edge'][1].split(':')[1])
                else:
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
                for intention in details['attacks']:
                    if intention['iter_num'] > threshold.iter_num:
                        cycle = intention['cycle']
                        addrs = str(tuple(sorted(cycle)))
                        if addrs not in self.reen_cycle2target:
                            print('reentrancy', tx_hash, addrs)
                            embed()
                        else:
                            t = self.reen_cycle2target[addrs]
                            if t == '0xc6b330df38d6ef288c953f1f2835723531073ce2':
                                continue
                            targets.append(t)
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
                if t not in eco_loss['ether']['reentrancy']:
                    eco_loss['ether']['reentrancy'][t] = 0
                eco_loss['ether']['reentrancy'][t] += Web3.fromWei(eth, 'ether')
            elif v == 'call-after-destruct' and not failed_data:
                suicided_contract = details['suicided_contract']
                self.cad.vul2txs[v].add(tx_hash)
                self.cad.vul2contrs[v].add(suicided_contract)
                if 'ETHER_TRANSFER' in results:
                    if suicided_contract not in eco_loss['ether']['call-after-destruct']:
                        eco_loss['ether']['call-after-destruct'][suicided_contract] = 0
                    eco_loss['ether']['call-after-destruct'][suicided_contract] += Web3.fromWei(results['ETHER_TRANSFER'], 'ether')

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

        if failed_data:
            self.failed_loss = eco_loss
        else:
            self.attack_loss = eco_loss

    def update_confirmed_vuls(self):
        self.confirmed_vuls = {
            'call-injection': self.parity_wallet,
            'reentrancy': self.attack_data.vul2contrs_open_sourced['reentrancy'],
            'integer-overflow': self.integer_overflow_contracts['confirmed'],
            'airdrop-hunting': self.attack_data.vul2contrs_open_sourced['airdrop-hunting']
        }
