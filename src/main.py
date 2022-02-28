import sys
from src.snort.snort import Snort
from src.runner import Runner


def main():
    conf = {
        'snort' : 'snort',
        'conf' : '/etc/snort/etc/snort.conf'
    }

    snort = Snort(conf)
    runner = Runner()
    
    pcap = sys.argv[1]
    r = runner._run_snort_alerts(snort, pcap)
    print(r)


if __name__ == "__main__":
    main()