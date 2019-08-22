from config import Config

from transaction_trace.local import EthereumDatabase, ContractTransactions, DatabaseName
from transaction_trace.basic_utils import DatetimeUtils

from related_works import RelatedWorks

from collections import defaultdict
from datetime import datetime
from dateutil.relativedelta import relativedelta
from copy import deepcopy
from web3 import Web3


class Thresholds(object):
    def __init__(self, hunting_time, iter_num, overflow_thr):
        self.hunting_time = hunting_time
        self.iter_num = iter_num
        self.overflow_thr = overflow_thr


class EvalUtil(object):
    def __init__(self, eval_data, idx_db_passwd='orzorz'):
        self.ed = eval_data
        self.related_works = RelatedWorks()
        self.zday = None

        # self.trace_db = EthereumDatabase("/mnt/data/bigquery/ethereum_traces", DatabaseName.TRACE_DATABASE)
        self.trace_db = None
        # self.tx_index_db = ContractTransactions(
        #     user="contract_txs_idx", passwd=idx_db_passwd, db="contract_txs_idx")
        self.tx_index_db = None

    def peak_table(self):
        peak_period = {
            'reentrancy': ('2016-05', '2016-06', '2016-08', '2016-09'),
            'call-injection': ('2017-06', '2017-07', '2017-07', '2017-08'),
            'integer-overflow': ('2018-03', '2018-04', '2018-05', '2018-06'),
            'airdrop-hunting': ('2018-08', '2018-09', '2019-01', '2019-02')
        }
        peak_result = {
            'before': defaultdict(set),
            'after': defaultdict(set)
        }
        for v in self.ed.confirmed_vuls:
            if v in peak_period:
                print(v, '...')
                cc = 0
                for c in self.ed.confirmed_vuls[v]:
                    for tx in self.ed.attack_data.contr2txs[v][c]:
                        if peak_period[v][1] <= self.ed.tx_time[tx][:7] <= peak_period[v][2]:
                            print(c)
                            cc += 1
                            txs = self.tx_index_db.read_transactions_of_contract(c)
                            for d in txs:
                                t = None
                                if d[:7] == peak_period[v][0]:
                                    t = 'before'
                                elif d[:7] == peak_period[v][-1]:
                                    t = 'after'
                                if t:
                                    for tx in txs[d]:
                                        peak_result[t][v].add(tx)
                            break
                print(v, cc)
        return peak_result



    def ci_eth_loss(self):
        with open(Config.CI_LOG_FILE, 'r') as f:
            lines = f.readlines()
            rows = []
            for line in lines:
                rows.append(eval(line.strip('\n')))

        cands = defaultdict(dict)
        for row in rows:
            if 'initWallet(address[],uint256,uint256)' in row['behavior']:
                if row['caller'] not in cands[row['entry']] or cands[row['entry']][row['caller']] > row['time']:
                    cands[row['entry']][row['caller']] = row['time']

        eth_loss = defaultdict(int)
        eth_dollar_loss = defaultdict(int)
        white_hat_save = {'eth': 0, 'dollar': 0}
        for entry in cands:
            print('entry:', entry)
            txs = self.tx_index_db.read_transactions_of_contract(entry)
            for d in txs:
                con = self.trace_db.get_connection(d)
                if con == None:
                    continue
                for row in con.read("traces", "transaction_hash, from_address, to_address, value, status, block_timestamp"):
                    if row['status'] and row['from_address'] == entry and row['to_address'] in cands[entry]:
                        tx_time = DatetimeUtils.time_to_str(row['block_timestamp'])
                        if tx_time > cands[entry][row['to_address']]:
                            eth = float(Web3.fromWei(row['value'], 'ether'))
                            if eth > 0:
                                print(row['transaction_hash'], eth)
                                eth_loss[entry] += eth
                                eth_dollar_loss[entry] += eth * self.ed.eth_price[tx_time[:10]]
                                if row['to_address'] in Config.white_hat_group:
                                    white_hat_save['eth'] += eth
                                    white_hat_save['dollar'] += eth * self.ed.eth_price[tx_time[:10]]

        return eth_loss, eth_dollar_loss, white_hat_save

    def dat_month2txs(self):
        begin = datetime(2015, 8, 1, 0, 0)
        month2txs_dat = dict()
        while begin < datetime(2019, 4, 1, 0, 0):
            month2txs_dat[DatetimeUtils.month_to_str(begin)] = {
                'airdrop-hunting': 0,
                'reentrancy': 0,
                'integer-overflow': 0,
                'call-injection': 0,
                'call-after-destruct': 0,
                'honeypot': 0
            }
            begin += relativedelta(months=1)

        for m in self.ed.month2txs:
            for v in self.ed.month2txs[m]:
                month2txs_dat[m][v] = len(self.ed.month2txs[m][v])

        return month2txs_dat

    def dat_contract_cdf(self):
        contr_cdf_dat = defaultdict(dict)
        for i in range(1, 101):
            contr_cdf_dat[i] = {
                'airdrop-hunting': 0,
                'reentrancy': 0,
                'integer-overflow': 0,
                'call-injection': 0,
                'call-after-destruct': 0,
                'honeypot': 0
            }
        for v in self.ed.attack_data.contr2txs:
            rows = []
            for c in self.ed.attack_data.contr2txs[v]:
                rows.append((c, len(self.ed.attack_data.contr2txs[v][c])))
            rows.sort(reverse=True, key=lambda x: x[1])
            l = len(rows)
            for i in range(1, l+1):
                row = rows[i-1]
                pos = int(i*100/l) if int(i*100/l) == i * \
                    100/l else int(i*100/l+1)
                contr_cdf_dat[pos][v] += row[1]*100 / \
                    len(self.ed.attack_data.vul2txs[v])
        for i in contr_cdf_dat:
            for v in contr_cdf_dat[i]:
                if contr_cdf_dat[i][v] == 0:
                    if i != 1:
                        contr_cdf_dat[i][v] = '?'
        return contr_cdf_dat

    def dat_bytecode_cdf(self):
        bytecode2txs = self.get_bytecode2txs()
        bytecode_cdf_dat = defaultdict(dict)
        for i in range(1, 101):
            bytecode_cdf_dat[i] = {
                'airdrop-hunting': 0,
                'reentrancy': 0,
                'integer-overflow': 0,
                'call-injection': 0,
                'call-after-destruct': 0,
                'honeypot': 0
            }
        for v in bytecode2txs:
            rows = []
            for h in bytecode2txs[v]:
                rows.append((h, len(bytecode2txs[v][h])))
            rows.sort(reverse=True, key=lambda x: x[1])
            l = len(rows)
            for i in range(1, l+1):
                row = rows[i-1]
                pos = int(i*100/l) if int(i*100/l) == i * \
                    100/l else int(i*100/l+1)
                bytecode_cdf_dat[pos][v] += row[1]*100 / \
                    len(self.ed.attack_data.vul2txs[v])
        for i in bytecode_cdf_dat:
            for v in bytecode_cdf_dat[i]:
                if bytecode_cdf_dat[i][v] == 0:
                    if i != 1:
                        bytecode_cdf_dat[i][v] = '?'
        return bytecode_cdf_dat

    def get_bytecode2txs(self):
        bytecode2txs = dict()
        for v in self.ed.attack_data.contr2txs:
            bytecode2txs[v] = defaultdict(set)
            for c in self.ed.attack_data.contr2txs[v]:
                if c not in self.ed.contract_cache:
                    continue
                bytecode_hash = self.ed.contract_cache[c]
                for tx_hash in self.ed.attack_data.contr2txs[v][c]:
                    bytecode2txs[v][bytecode_hash].add(tx_hash)
        return bytecode2txs

    def update_zday(self):
        zday = deepcopy(self.ed.confirmed_vuls)
        zday['call-injection'].clear()
        zday['airdrop-hunting'].remove(
            '0x86c8bf8532aa2601151c9dbbf4e4c4804e042571')
        zday['reentrancy'].remove('0xf91546835f756da0c10cfa0cda95b15577b84aa7')
        zday['reentrancy'].remove('0xd2e16a20dd7b1ae54fb0312209784478d069c7b0')

        for w in self.related_works.datasets:
            d = self.related_works.datasets[w]
            for v in d.typed_vulnerable_contracts:
                for c in d.typed_vulnerable_contracts[v]:
                    if c in zday[v]:
                        zday[v].remove(c)

        for w in self.ed.related_works_result:
            for v in self.ed.related_works_result[w]:
                for c in self.ed.related_works_result[w][v]:
                    if c in zday[v]:
                        zday[v].remove(c)

        for c in self.ed.integer_overflow_cve:
            if c in zday['integer-overflow']:
                zday['integer-overflow'].remove(c)

        zday['honeypot'] = self.ed.honeypot_contracts['zday']

        self.zday = zday

    def print_table_two(self):
        total = defaultdict(set)
        atx = defaultdict(set)
        zatx = defaultdict(set)
        for v in self.ed.confirmed_vuls:
            print(v, len(self.ed.confirmed_vuls[v]))
            for c in self.ed.confirmed_vuls[v]:
                total['vct'].add(c)
                for tx in self.ed.attack_data.contr2txs[v][c]:
                    atx[v].add(tx)
                    total['atx'].add(tx)
            print(v, len(atx[v]))
        print('final total', len(total['vct']), len(total['atx']))
        for v in self.zday:
            print(v, len(self.zday[v]))
            for c in self.zday[v]:
                total['zvct'].add(c)
                for tx in self.ed.attack_data.contr2txs[v][c]:
                    zatx[v].add(tx)
                    total['zatx'].add(tx)
            print(v, len(zatx[v]))
        print('zday total', len(total['zvct']), len(total['zatx']))
        for v in self.ed.failed_data.vul2txs:
            if v not in ('honeypot', 'call-after-destruct'):
                print(v, len(self.ed.failed_data.vul2txs[v]))
                for tx in self.ed.failed_data.vul2txs[v]:
                    total['attemp_tx'].add(tx)
        print('attemp total', len(total['attemp_tx']))

    def cmp_related_works_wo_vuls(self):
        events = {
            'reentrancy': [
                '0xf91546835f756da0c10cfa0cda95b15577b84aa7',
                '0xd2e16a20dd7b1ae54fb0312209784478d069c7b0'
            ],
        }
        events['call-injection'] = self.ed.parity_wallet
        reported_ct = defaultdict(set)
        reported_tx = defaultdict(set)

        related_work_candidates = defaultdict(set)

        for w in self.related_works.datasets:
            dataset = self.related_works.datasets[w]
            for v in dataset.typed_vulnerable_contracts:
                for c in dataset.typed_vulnerable_contracts[v]:
                    related_work_candidates[v].add(c)
        for w in self.ed.related_works_result:
            for v in self.ed.related_works_result[w]:
                for c in self.ed.related_works_result[w][v]:
                    related_work_candidates[v].add(c)

        for v in self.ed.confirmed_vuls:
            for c in self.ed.confirmed_vuls[v]:
                if c in related_work_candidates[v]:
                    reported_ct[v].add(c)
                    for tx in self.ed.attack_data.contr2txs[v][c]:
                        reported_tx[v].add(tx)

        # import IPython;IPython.embed()
        return reported_ct, reported_tx, related_work_candidates

    def introduction_data(self):
        zzday = set()
        for v in ('reentrancy', 'integer-overflow'):
            zzday = zzday.union(self.zday[v])
        print("{} zero-day vulnerabilities with ...".format(len(zzday)))

        attempted_txs = set()
        succeed_txs = set()
        for v in self.ed.attack_data.contr2txs:
            for c in self.ed.attack_data.contr2txs[v]:
                conf = False
                if c in self.ed.confirmed_vuls[v]:
                    conf = True
                for tx in self.ed.attack_data.contr2txs[v][c]:
                    if conf:
                        succeed_txs.add(tx)
                    attempted_txs.add(tx)

        for v in self.ed.failed_data.vul2txs:
            for tx in self.ed.failed_data.vul2txs[v]:
                attempted_txs.add(tx)
        print("attemped txs: {}".format(len(attempted_txs)))
        print("succeed txs: {}".format(len(succeed_txs)))
        print("{} of all the ".format(len(succeed_txs)/len(attempted_txs)))

        confirmed_airdrop_txs = set()
        for c in self.ed.confirmed_vuls['airdrop-hunting']:
            for tx in self.ed.attack_data.contr2txs['airdrop-hunting'][c]:
                confirmed_airdrop_txs.add(tx)
        print("{} of ... targeting {} ... using new attack tactics".format(
            len(confirmed_airdrop_txs)/len(succeed_txs),
            len(self.ed.confirmed_vuls['airdrop-hunting'])))

        oveflow_ztxs = set()
        known_vuls_confirmed_txs = set()
        for v in self.ed.confirmed_vuls:
            if v in ('integer-overflow'):
                for c in self.ed.confirmed_vuls[v]:
                    for tx in self.ed.attack_data.contr2txs[v][c]:
                        known_vuls_confirmed_txs.add(tx)
                        if v == 'integer-overflow' and c in self.zday['integer-overflow']:
                            oveflow_ztxs.add(tx)

        print("{} of all the ... integer overflow ... {} previously ...".format(
            len(oveflow_ztxs)/len(known_vuls_confirmed_txs), len(self.zday['integer-overflow'])))

        local_attemp_txs_rc = {'all': set(), 'rc': set()}
        local_confirm_txs_rc = {'all': set(), 'rc': set()}
        local_attemp_txs_ai = {'all': set(), 'ai': set()}
        local_confirm_txs_ai = {'all': set(), 'ai': set()}
        for v in self.ed.attack_data.vul2txs:
            for tx in self.ed.attack_data.vul2txs[v]:
                if self.ed.tx_time[tx] > "2015-08-01" and self.ed.tx_time[tx] < "2017-08-01":
                    if tx in succeed_txs:
                        local_confirm_txs_rc['all'].add(tx)
                        if v in ('reentrancy', 'call-injection'):
                            local_confirm_txs_rc['rc'].add(tx)
                elif self.ed.tx_time[tx] > "2017-09-01" and self.ed.tx_time[tx] < "2019-03-01":
                    if tx in succeed_txs:
                        local_confirm_txs_ai['all'].add(tx)
                        if v in ('airdrop-hunting', 'integer-overflow'):
                            local_confirm_txs_ai['ai'].add(tx)

        for v in self.ed.failed_data.vul2txs:
            for tx in self.ed.failed_data.vul2txs[v]:
                if self.ed.tx_time[tx] > "2015-08-01" and self.ed.tx_time[tx] < "2017-08-01":
                    local_attemp_txs_rc['all'].add(tx)
                    if v in ('reentrancy', 'call-injection'):
                        local_attemp_txs_rc['rc'].add(tx)
                elif self.ed.tx_time[tx] > "2017-09-01" and self.ed.tx_time[tx] < "2019-03-01":
                    local_attemp_txs_ai['all'].add(tx)
                    if v in ('airdrop-hunting', 'integer-overflow'):
                        local_attemp_txs_ai['ai'].add(tx)

        print("{} attemped, {} confirmed between 2015.8 and 2017.8".format(len(local_attemp_txs_rc['rc'])/len(
            local_attemp_txs_rc['all']), len(local_confirm_txs_rc['rc'])/len(local_confirm_txs_rc['all'])))

        print("{} attemped, {} confirmed between 2017.9 and 2019.3".format(len(local_attemp_txs_ai['ai'])/len(
            local_attemp_txs_ai['all']), len(local_confirm_txs_ai['ai'])/len(local_confirm_txs_ai['all'])))

        # incident_txs = set()
        # incident_contracts = set()
        # incident_contracts.add('0xd2e16a20dd7b1ae54fb0312209784478d069c7b0')
        # incident_contracts.add('0xf91546835f756da0c10cfa0cda95b15577b84aa7')
        # for c in self.ed.parity_wallet:
        #     incident_contracts.add(c)
        # for v in self.ed.attack_data.contr2txs:
        #     for c in self.ed.attack_data.contr2txs[v]:
        #         if c in incident_contracts:
        #             for tx in self.ed.attack_data.contr2txs[v][c]:
        #                 incident_txs.add(tx)
        # print("excluding {} of these famous incidents".format(
        #     len(incident_txs)/len(succeed_txs)))

        # our_candidates, related_works_candidates, reported, not_reported = self.cmp_related_works_wo_vuls()
        # reported_contracts = set()
        # for w in reported:
        #     for c in reported[w]:
        #         if c not in incident_contracts:
        #             reported_contracts.add(c)
        # reported_txs = set()
        # cve_txs = set()
        # for v in self.ed.attack_data.contr2txs:
        #     for c in self.ed.attack_data.contr2txs[v]:
        #         if c in reported_contracts and c in self.ed.confirmed_vuls[v]:
        #             for tx in self.ed.attack_data.contr2txs[v][c]:
        #                 reported_txs.add(tx)
        #         if c in self.ed.integer_overflow_cve and c not in related_works_candidates:
        #             for tx in self.ed.attack_data.contr2txs[v][c]:
        #                 cve_txs.add(tx)
        # print("only {} of confirmed ... are targeting".format(
        #     len(reported_txs)/len(succeed_txs)))
        # print("{} vulnerabilities reported".format(len(reported_contracts)))
        # print("{} is targeting {} vulnerabilities ... CVE database".format(
        #     len(cve_txs)/len(succeed_txs), len(self.ed.integer_overflow_cve)))

        # unknown_vuls = set()
        # unknown_txs = set()
        # for v in self.ed.attack_data.vul2contrs:
        #     for c in self.ed.attack_data.vul2contrs[v]:
        #         if c not in incident_contracts and c not in self.ed.integer_overflow_cve and c not in related_works_candidates and c in self.ed.confirmed_vuls[v]:
        #             unknown_vuls.add(c)
        # for v in self.ed.attack_data.contr2txs:
        #     for c in self.ed.attack_data.contr2txs[v]:
        #         if c in unknown_vuls:
        #             for tx in self.ed.attack_data.contr2txs[v][c]:
        #                 unknown_txs.add(tx)
        # print("{} is actually targeting {} previously-unknown".format(
        #     len(unknown_txs)/len(succeed_txs), len(unknown_vuls)))

        # missed_vuls = set()
        # missed_txs = set()
        # for v in self.ed.attack_data.vul2contrs:
        #     for c in self.ed.attack_data.vul2contrs[v]:
        #         if c in self.ed.confirmed_vuls[v] and c not in related_works_candidates:
        #             missed_vuls.add(c)
        # for v in self.ed.attack_data.contr2txs:
        #     for c in self.ed.attack_data.contr2txs[v]:
        #         if c in self.ed.confirmed_vuls[v] and c in missed_vuls:
        #             for tx in self.ed.attack_data.contr2txs[v][c]:
        #                 missed_txs.add(tx)
        # print("{} of confirmed adversarial  transactions  are  targeting  {}  vulnerabilities".format(
        #     len(missed_txs)/len(succeed_txs), len(missed_vuls)))
