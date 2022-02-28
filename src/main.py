import sys
from src.snort.snort import Snort
from src.runner import Runner


def main():
    conf = {
        'snort' : 'snort',
        'conf' : '/etc/snort/etc/snort.conf',
        'extra_args': '-l /etc/snort/logs'
    }

    snort = Snort(conf)
    runner = Runner()
    
    pcap = sys.argv[1]
    rule = ["alert icmp any any <> any any (msg: 'Pinging BOTH SIDE'; sid:1; )", "alert icmp any any -> 8.8.8.8 any (msg: 'Pinging to'; sid:2;)"]
    r = runner._run_snort_alerts(snort, pcap, rule)
    print(r)


if __name__ == "__main__":
    main()