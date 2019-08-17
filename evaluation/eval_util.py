from config import Config

from transaction_trace.local import EthereumDatabase
from transaction_trace.basic_utils import DatetimeUtils

from related_works import RelatedWorks

from collections import defaultdict
from datetime import datetime
from dateutil.relativedelta import relativedelta
from copy import deepcopy



class Thresholds(object):
    def __init__(self, hunting_time, iter_num, overflow_thr):
        self.hunting_time = hunting_time
        self.iter_num = iter_num
        self.overflow_thr = overflow_thr


class EvalUtil(object):
    def __init__(self, eval_data):
        self.ed = eval_data
        self.related_works = RelatedWorks()
        self.zday = None

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
                contr_cdf_dat[pos][v] += row[1]*100/len(self.ed.attack_data.vul2txs[v])
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
                bytecode_cdf_dat[pos][v] += row[1]*100/len(self.ed.attack_data.vul2txs[v])
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
        zday['airdrop-hunting'].remove('0x86c8bf8532aa2601151c9dbbf4e4c4804e042571')
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
                if v == 'honeypot':
                    continue
                for tx in self.ed.attack_data.contr2txs[v][c]:
                    atx[v].add(tx)
                    total['atx'].add(tx)
            print(v, len(atx[v]))
        print('final total', len(total['vct']), len(total['atx']))
        for v in self.zday:
            print(v, len(self.zday[v]))
            for c in self.zday[v]:
                total['zvct'].add(c)
                if v != 'honeypot':
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
        our_candidates = set()
        related_works_candidates = set()
        reported = defaultdict(set)
        not_reported = defaultdict(set)

        for w in self.related_works.datasets:
            dataset = self.related_works.datasets[w]
            for c in dataset.all_vulnerable_contracts:
                related_works_candidates.add(c)

        for v in self.ed.attack_data.vul2contrs:
            for c in self.ed.attack_data.vul2contrs[v]:
                our_candidates.add(c)
        for c in our_candidates:
            for w in self.related_works.datasets:
                dataset = self.related_works.datasets[w]
                if c in dataset.all_vulnerable_contracts:
                    reported[w].add(c)
                elif c in self.ed.create_time and DatetimeUtils.time_to_str(self.ed.create_time[c]) <= Config.dataset_latest_time[w]:
                    not_reported[w].add(c)

        return our_candidates, related_works_candidates, reported, not_reported

    def introduction_data(self):
        zzday = set()
        for v in ('reentrancy', 'integer-overflow', 'honeypot'):
            zzday.union(self.zday[v])
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
        for c in self.zday['integer-overflow']:
            for tx in self.ed.attack_data.contr2txs['integer-overflow'][c]:
                oveflow_ztxs.add(tx)

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

        print("{} attemped, {} confirmed between 2015.8 and 2017.8".format(len(local_attemp_txs_rc['rc'])/len(local_attemp_txs_rc['all']), len(local_confirm_txs_rc['rc'])/len(local_confirm_txs_rc['all'])))

        print("{} attemped, {} confirmed between 2017.9 and 2019.3".format(len(local_attemp_txs_ai['ai'])/len(local_attemp_txs_ai['all']), len(local_confirm_txs_ai['ai'])/len(local_confirm_txs_ai['all'])))

        import IPython;IPython.embed()

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
