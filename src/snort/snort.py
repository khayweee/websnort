from datetime import datetime
from pathlib import Path
import glob
import os
import stat
import re
import shlex
from subprocess import PIPE, Popen
from typing import List
import logging
import sys

# Example Alert
# 02/26/22-21:02:33.357151  [**] [1:1000004:0] Pinging... [**] [Priority: 0] {ICMP} 192.168.52.129 -> 8.8.8.8
ALERT_PATTERN = re.compile(
    r"(?P<timestamp>\d{2}/\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+\[\d+:(?P<sid>\d+):(?P<revision>\d+)\] "
    r"(?P<message>.+) \[\*\*\]\s+(\[Classification: (?P<classtype>.+)\] ){0,1}"
    r"\[Priority: (?P<priority>\d+)\] \{(?P<protocol>\w+)\} "
    r"(?P<src>.+) \-\> (?P<dest>.+)")

VERSION_PATTERN = re.compile(
    r".*\s+Version (?P<version>[\d\.]+ .*)"
)

# Example
#   Num      SID GID Rev     Checks   Matches    Alerts           Microsecs  Avg/Check  Avg/Match Avg/Nonmatch   Disabled
#   ===      === === ===     ======   =======    ======           =========  =========  ========= ============   ========
#     1        1   1   0          8         8         8                   0        0.1        0.1          0.0          0
#     2        2   1   0          8         4         4                   0        0.0        0.0          0.0          0
PROFILE_RULE_PATTERN = re.compile(
    r"^\s+(?P<num>\d+)\s+(?P<sid>\d+)\s+(?P<gid>\d+)\s+(?P<rev>\d+)\s+"
    r"(?P<checks>\d+)\s+(?P<matches>\d+)\s+(?P<alerts>\d+)\s+(?P<microsecs>\d+)\s+"
    r"(?P<avg_check>\d+(\.\d+)?)\s+(?P<avg_match>\d+(\.\d+)?)\s+(?P<avg_nonmatch>\d+(\.\d+)?)\s+"
    r"(?P<disabled>\d+)$"
)

DEFAULT_RULE_PATH = "/etc/snort/rules/check_default.rules"
DEFAULT_OUTPUT_PATH = "/var/log/snort/"
DEFAULT_RULE_PROFILE_FILENAME_PREFIX = "rules_stats"

logger = logging.getLogger(__name__)


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
                    rulepath: Path to rules directory
                    output: Path to output any Snort output
        """
        self.conf = conf

    def _snort_cmd(self, pcap):
        """
        Given a pcap filaname, get the commandline to run

        :param pcap: Pcap filename to scan
        :returns: list of snort command args to scan supplied pcap file
        """
        cmdline = "'{snort}' -A console -N -y -c '{conf}' {extra_args} -r '{pcap}'"\
            .format(snort=self.conf['snort'],
                    conf=self.conf['conf'],
                    extra_args=self.conf.get('extra_args', ''),
                    pcap=pcap)
        if 'nt' in os.name:
            # Windows Operating System
            cmdline = "cmd.exe /c " + cmdline
        return shlex.split(cmdline)

    def _rule_performance_cmd(self, output_dir: str = None, filename_prefix: str = None):
        """
        Read the filename produced my config profile_rules snort preprocessor

        From Snort Manual Ver. 2.9.16
        2.5 Performance Profiling
        http://manual-snort-org.s3-website-us-east-1.amazonaws.com/node20.html#SECTION00351000000000000000

        :param output_dir: The directory of snort outuput. Default /var/log/snort
        :param filename_prefix: The name of the output file. e.g. rule_stats.txt
        """
        if not output_dir:
            output_dir = Path(DEFAULT_OUTPUT_PATH)
        else:
            output_dir = Path(output_dir)

        if not filename_prefix:
            filename_prefix = DEFAULT_RULE_PROFILE_FILENAME_PREFIX

        list_of_files = list(output_dir.glob(filename_prefix + ".*"))
        latest_file = str(max(list_of_files, key=os.path.getctime))

        cmdline = "'cat {latest_file}'"\
            .format(latest_file=latest_file)
        return shlex.split(cmdline)

    def run(self, pcap, rules: List[str] = None) -> list:
        """
        Runs snort against supplied pcap.

        :param pcap: Filepath to pcap file to scan
        :returns: tuple of version, list of alerts
        """
        if rules:
            self.write_rules(rules)

        proc = Popen(self._snort_cmd(pcap), stdout=PIPE,
                     stderr=PIPE, universal_newlines=True)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            raise Exception("\n".join(["Exception failed return code: {code}"
                            .format(code=proc.returncode), stderr or ""]))
        return (self._parse_version(stderr),
                [x for x in self._parse_alert(stdout)],
                [x for x in self._parse_rule_profile(stderr)])

    def run_performance(self, pcap, rules: List[str] = None):
        if rules:
            self.write_rules(rules)
        pass

    def write_rules(self, rules: List[str]) -> None:
        """
        Create local.rules files for snort to ingest as rules
        """
        rule_path = self.conf.get('rulepath', DEFAULT_RULE_PATH)
        with open(rule_path, 'w+') as f:
            for rule in rules:
                logger.info('Writing: [%s]', rule)
                f.writelines(rule)
                f.writelines('\n')
        os.chmod(rule_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        # TODO: Change/Add autoincremental SID values to each snort rule

    def _parse_rule_profile(self, output):
        """
        Parses the supplied output and yields any rule
        :param output: A string containing the output of snort
        :returns: A generator
        """
        for x in output.splitlines():
            match = PROFILE_RULE_PATTERN.match(x)
            if match:
                rec = {
                    'num': int(match.group('num')),
                    'sid': int(match.group('sid')),
                    'gid': int(match.group('gid')),
                    'rev': int(match.group('rev')),
                    'checks': int(match.group('checks')),
                    'matches': int(match.group('matches')),
                    'alerts': int(match.group('alerts')),
                    'microsecs': int(match.group('microsecs')),
                    'avg_check': float(match.group('avg_check')),
                    'avg_match': float(match.group('avg_match')),
                    'avg_nonmatch': float(match.group('avg_nonmatch')),
                    'disabled': int(match.group('disabled'))
                }
                yield rec

    def _parse_version(self, output):
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

    def _parse_alert(self, output):
        """
        Parses the supplied output and yields any alerts.

        Example alert format:
        02/26/22-21:02:33.357151  [**] [1:1917:11] INDICATOR-SCAN UPnP service discover attempt [**] [Classification: Detection of a Network Scan] [Priority: 3] {UDP} 10.1.1.132:58650 -> 239.255.255.250:1900
        02/26/22-21:02:33.357151  [**] [1:1000004:0] Pinging... [**] [Priority: 0] {ICMP} 192.168.52.129 -> 8.8.8.8
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
    """
    For Debugging Purposes only
    This module is intended for use as an imported API
    """
    conf = {
        'snort': 'snort',
        'conf': '/etc/snort/etc/snort.conf'
    }

    snort = Snort(conf)

    pcap = sys.argv[1]
    r = snort.run(pcap)
    print(r)
