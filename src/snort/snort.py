from datetime import datetime
import os
import re
import shlex
from subprocess import PIPE, Popen

import sys

ALERT_PATTERN = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
    r"(?P<message>.+) \[\*\*\]\s+(\[Classification: (?P<classtype>.+)\] ){0,1}"
    r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>\w+)\} "
    r"(?P<src>.+) \-\> (?P<dest>.+)")

VERSION_PATTERN = re.compile(
    r".*\s+Version (?P<version>[\d\.]+ .*)"
)


class Snort(object):
    """
    Module to interfact with local Snort IDS installation
    """

    def __init__(self, conf):
        """
        Runner for interacting with Snort IDS
        :param conf: dict containing
                    path: Path to Snort Binary
                    config: Path to Snort Config
                    output: Path to output any Snort output
        """
        self.conf = conf
    
    def _snort_cmd(self, pcap):
        """
        Given a pcap filaname, get the commandline to run

        :param pcap: Pcap filename to scan
        :returns: list of snort command args to scan supplied pcap file
        """
        cmdline = "'{snort}' -A console -N -y -c '{conf}' -r '{pcap}'"\
            .format(snort=self.conf['snort'],
                    conf=self.conf['conf'],
                    pcap=pcap)
        if 'nt' in os.name:
            cmdline = "cmd.exe /c " + cmdline
        return shlex.split(cmdline)
    
    def run(self, pcap):
        """
        Runs snort against supplied pcap.

        :param pcap: Filepath to pcap file to scan
        :returns: tuple of version, list of alerts
        """
        proc = Popen(self._snort_cmd(pcap), stdout=PIPE,
                    stderr=PIPE, universal_newlines=True)
        stdout, stderr = proc.communicate()

        if proc.returncode != 0:
            raise Exception("\n".join(["Exception failed return code: {code}" \
                            .format(proc.returncode), stderr or ""]))
        return (self.parse_version(stderr),
                [ x for x in self.parse_alert(stdout)])

    def parse_version(self, output):
        """
        Parses the supplied output and returns the version string.

        :param output: A string containing the output of running snort.
        :returns: Version string for the version of snort run. None if not found.
        """
        for x in output.splitlines():
            match = VERSION_PATTERN.match(x)
            if match:
                return match.group('version').strip()
        return None
    
    def parse_alert(self, output):
        """
        Parses the supplied output and yields any alerts.

        Example alert format:
        01/28/14-22:26:04.885446  [**] [1:1917:11] INDICATOR-SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 10.1.1.132:58650 -> 239.255.255.250:1900

        :param output: A string containing the output of running snort
        :returns: Generator of snort alert dicts
        """
        for x in output.splitlines():
            match = ALERT_PATTERN.match(x)
            if match:
                rec = {'timestamp': datetime.strptime(match.group('timestamp'),
                                                    '%m/%d/%y-%H:%M:%S.%f'),
                    'sid': int(match.group('sid')),
                    'revision': int(match.group('revision')),
                    'priority': int(match.group('priority')),
                    'message': match.group('message'),
                    'source': match.group('src'),
                    'destination': match.group('dest'),
                    'protocol': match.group('protocol'),
                    }
                if match.group('classtype'):
                    rec['classtype'] = match.group('classtype')
                yield rec

if __name__ == '__main__':
    conf = {
        'snort' : 'snort',
        'conf' : '/etc/snort/etc/snort.conf'
    }
    
    snort = Snort(conf)
    
    pcap = sys.argv[1]
    r = snort.run(pcap)
    print(r)

    