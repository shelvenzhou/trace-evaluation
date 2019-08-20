import json
import logging
import sys
from collections import defaultdict

import transaction_trace
from IPython import embed
from transaction_trace.local import EthereumDatabase

l = logging.getLogger("fn_set_tx_count")


def main(db_folder):
    benchmark = set()
    with open("fn_set.json", "r") as f:
        raw_data = json.load(f)
        for vul_type in raw_data:
            for ct in raw_data[vul_type]:
                benchmark.add(ct)

    transaction_count = defaultdict(set)

    db = EthereumDatabase(db_folder)
    for conn in db.get_all_connnections():
        l.info("construct for %s", conn)
        for row in conn.read_traces():
            if row['trace_type'] not in ('call', 'create', 'suicide'):
                continue
            if row['status'] == 0:
                continue

            to_addr = row["to_address"]
            if to_addr in benchmark:
                transaction_count[to_addr].add(row["transaction_hash"])

    with open("fn_set_tx_count.json", "w+") as f:
        json.dump({k: list(v) for k, v in transaction_count.items()}, f, indent="\t")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 %s db_folder" % sys.argv[0])
        exit(-1)

    main(sys.argv[1])
