from related_works import RelatedWorks, RelatedWorksRunner

from IPython import embed


def run_related_works():
    runner = RelatedWorksRunner('/home/xiangjie/logs/evaluation/deployed_bytecodes/')
    # runner.run_mythril()
    runner.run_securify()

if __name__ == "__main__":
    run_related_works()
