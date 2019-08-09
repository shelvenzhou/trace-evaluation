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
        return honeypot.details["status"] == "INITIALIZED" \
            or honeypot.details["tx_count"] > 20
