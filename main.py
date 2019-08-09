from related_works import RelatedWorks, RelatedWorksRunner
from evaluation import EvalData

from IPython import embed


def run_related_works():
    runner = RelatedWorksRunner('/home/xiangjie/logs/evaluation/deployed_bytecodes/')
    # runner.run_mythril()
    # runner.run_securify()
    runner.run_teether()

if __name__ == "__main__":
    # run_related_works()

    ed = EvalData('/home/xiangjie/logs/attack-candidates-20190808230103.log', '/home/xiangjie/logs/failed-attacks-20190807143556.log', 'orzorz')

    embed()
