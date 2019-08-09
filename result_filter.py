def move(item, from_list, to_list):
    from_list.remove(item)
    to_list.append(item)


def honeypot_filter(honeypot):
    return honeypot.details["status"] == "INITIALIZED" \
        or honeypot.details["tx_count"] > 20


class ResultFilter:
    @staticmethod
    def filter_honeypot_results(honeypots):
        filtered = list()
        for h in honeypots:
            if honeypot_filter(h):
                move(h, honeypots, filtered)
        return filtered
