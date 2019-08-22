from related_works import RelatedWorks, RelatedWorksRunner
from evaluation import EvalData, Thresholds, EvalPatchs, EvalUtil

from IPython import embed


def run_related_works():
    runner = RelatedWorksRunner('/home/xiangjie/logs/evaluation/cad_bytecodes/')
    # runner.run_mythril()
    # runner.run_securify()
    runner.run_teether()

if __name__ == "__main__":
    # run_related_works()

    ed = EvalData('/Users/jay/Desktop/w/logs/attack-candidates-20190813165526.log', '/Users/jay/Desktop/w/logs/failed-attacks-20190813165526.log', 'orzorz')
    ep = EvalPatchs(ed)

    ed.extract_data(Thresholds(3, 1, 10**72), Thresholds(3, 1, 10**72))
    ep.replace_call_injection_data(ed.attack_data, ed.month2txs, ed.tx_time)
    ep.replace_honey_pot(ed.attack_data, '/Users/jay/Desktop/w/logs/honeypot-20190812.log')
    ep.append_tod(ed, '/Users/jay/Desktop/w/logs/tod-20190814.log', '/Users/jay/Desktop/w/logs/failed-tod-20190814.log')
    ed.update_confirmed_vuls()
    eu = EvalUtil(ed)
    eu.update_zday()

    embed()
