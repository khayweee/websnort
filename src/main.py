import sys
from src.snort.snort import Snort
from src.runner import Runner


if __name__ == "__main__":
    conf = {
        'snort' : 'snort',
        'conf' : '/etc/snort/etc/snort.conf'
    }

    snort = Snort(conf)
    runner = Runner()
    
    pcap = sys.argv[1]
    r = runner._run_snort_alerts(snort, pcap)
    print(r)