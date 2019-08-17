from related_works import RelatedWorks, RelatedWorksRunner
from evaluation import EvalData, Thresholds, EvalPatchs, EvalUtil

from IPython import embed


def run_related_works():
    runner = RelatedWorksRunner('/home/xiangjie/logs/evaluation/deployed_bytecodes/')
    # runner.run_mythril()
    # runner.run_securify()
    runner.run_teether()

if __name__ == "__main__":
    # run_related_works()

    ed = EvalData('/home/xiangjie/logs/attack-candidates-20190813165526.log', '/home/xiangjie/logs/failed-attacks-20190813165526.log', 'orzorz')
    ep = EvalPatchs(ed)

    ed.extract_data(Thresholds(3, 1, 10**72), Thresholds(0, 0, 0))
    ep.replace_call_injection_data(ed.attack_data, ed.tx_time)
    ed.update_confirmed_vuls()
    eu = EvalUtil(ed)
    eu.update_zday()

    embed()
