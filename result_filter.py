def move(item, from_list, to_list):
    from_list.remove(item)
    to_list.append(item)


class ResultFilter:

    @staticmethod
    def honeypot_filter(honeypot):
        """
        Filter contract which is definitely not honeypot,
        no matter whether it's confirmed or failed
        """
        return honeypot.details["tx_count"] > 20 \
            or len(honeypot.details["init_txs"]) > 3 \
            or len(honeypot.details["withdraw_txs"]) > 3 \
            or honeypot.results["bonus"] == 0 \
            or honeypot.results["profits"] == 0 \
            or honeypot.details["status"] != "WITHDRAWED" \
            or (honeypot.details["status"] == "WITHDRAWED" and honeypot.results["left"] > 1000)
