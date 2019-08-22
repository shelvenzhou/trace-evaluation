from config import Config

from transaction_trace.analysis.results import AttackCandidateExporter

from collections import defaultdict
from web3 import Web3


class EvalPatchs(object):
    def __init__(self, eval_data):
        self.ed = eval_data

    def append_tod(self, eval_data, tod_log_path, failed_tod_log_path):
        with open(tod_log_path, 'rb') as f:
            attack_candidates = AttackCandidateExporter.load_candidates(f)
        with open(failed_tod_log_path, 'rb') as f:
            failed_candidates = AttackCandidateExporter.load_candidates(f)

        abnormal_data = {eval_data.attack_data: attack_candidates, eval_data.failed_data: failed_candidates}
        for data in abnormal_data:
            for cand in abnormal_data[data]:
                v = cand.type
                details = cand.details
                results = cand.results
                if v != 'transaction-order-dependence-checker':
                    continue
                target = details['contract']
                data.vul2contrs[v].add(target)
                if self.ed.open_source_contract(target):
                    data.vul2contrs_open_sourced[v].add(target)
                for affected_txs in results['affected_txs']:
                    tx_hash = affected_txs['affected_tx']
                    data.vul2txs[v].add(tx_hash)
                    if target not in data.contr2txs[v]:
                        data.contr2txs[v][target] = set()
                    data.contr2txs[v][target].add(tx_hash)


    def move_airdrop_data_from_failed(self):
        to_remove = list()
        for cand in self.ed.failed_candidates:
            v = cand.type
            details = cand.details
            results = cand.results
            if v == 'airdrop-hunting' and details['slave_number'] == details['hunting_time'] and len(results) > 0:
                to_remove.append(cand)
        for cand in to_remove:
            self.ed.attack_candidates.append(cand)
            self.ed.failed_candidates.remove(cand)


    def replace_honey_pot(self, abnormal_data, honeypot_log_path):
        abnormal_data.vul2txs['honeypot'].clear()
        abnormal_data.vul2contrs['honeypot'].clear()
        abnormal_data.contr2txs['honeypot'].clear()
        abnormal_data.vul2contrs_open_sourced['honeypot'].clear()

        with open(honeypot_log_path, 'rb') as f:
            candidates = AttackCandidateExporter.load_candidates(f)
        for cand in candidates:
            v = cand.type
            details = cand.details

            if v == 'honeypot':
                target = details['contract']
                if target in self.ed.honeypot_contracts['candidates']:
                    abnormal_data.vul2contrs[v].add(target)
                    if self.ed.open_source_contract(target):
                        abnormal_data.vul2contrs_open_sourced[v].add(target)
                    for tx in details['profit_txs']:
                        abnormal_data.vul2txs[v].add(tx)
                        if target not in abnormal_data.contr2txs[v]:
                            abnormal_data.contr2txs[v][target] = set()
                        abnormal_data.contr2txs[v][target].add(tx)

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
                    if addrs not in self.ed.reen_addrs2target:
                        print(tx_hash, addrs)
                        continue
                    targets.append(self.ed.reen_addrs2target[addrs])
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
                if self.ed.open_source_contract(target):
                    abnormal_data.vul2contrs_open_sourced[v].add(target)
        return eth_lost

    def replace_call_injection_data(self, abnormal_data, month2txs, tx_time):
        for m in month2txs:
            month2txs[m]['call-injection'].clear()
        abnormal_data.vul2txs['call-injection'].clear()
        abnormal_data.vul2contrs['call-injection'].clear()
        abnormal_data.contr2txs['call-injection'].clear()
        abnormal_data.vul2contrs_open_sourced['call-injection'].clear()

        with open(Config.CI_LOG_FILE, 'r') as f:
            lines = f.readlines()
            rows = []
            for line in lines:
                rows.append(eval(line.strip('\n')))

        white_hat_txs = set()
        for row in rows:
            tx_hash = row['tx_hash']
            tx_time[tx_hash] = row['time']
            tx_month = row['time'][:7]
            if row['caller'] in Config.white_hat_group:
                white_hat_txs.add(tx_hash)
            if tx_month not in month2txs:
                month2txs[tx_month] = defaultdict(set)
            month2txs[row['time'][:7]]['call-injection'].add(tx_hash)
            abnormal_data.vul2txs['call-injection'].add(tx_hash)
            abnormal_data.vul2contrs['call-injection'].add(row['entry'])
            if row['entry'] not in abnormal_data.contr2txs['call-injection']:
                abnormal_data.contr2txs['call-injection'][row['entry']] = set()
            abnormal_data.contr2txs['call-injection'][row['entry']
                                                      ].add(tx_hash)
            if self.ed.open_source_contract(row['entry']):
                abnormal_data.vul2contrs_open_sourced['call-injection'].add(
                    row['entry'])
            if 'initWallet(address[],uint256,uint256)' in row['behavior']:
                self.ed.parity_wallet.add(row['entry'])

        return white_hat_txs
