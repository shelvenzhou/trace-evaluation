from related_works import RelatedWorks
from eval_util import EvalUtil, Thresholds

from IPython import embed

from related_works import RelatedWorks

if __name__ == "__main__":
    eu = EvalUtil('/home/shelven/Documents/smart-contract/transaction_trace_logs/attack-candidates-20190731110423.log', '/home/xiangjie/logs/failed-attacks-20190731110423.log', 'orzorz')
    attack_th = Thresholds(5, 0)
    failed_th = Thresholds(0, 0)
    eu.extract_data(attack_th, failed_th)
    eu.replace_call_injection_data(eu.attack_data)
    honeypot_eth_loss = eu.replace_honey_pot(eu.attack_data, '/home/xiangjie/logs/attack-candidates-20190801205825.log')

    embed()
