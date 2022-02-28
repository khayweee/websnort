"""
Main running logic for running pcap
"""
import sys
from datetime import datetime
from multiprocessing.pool import ThreadPool
from typing import Optional, List

from src.snort.snort import Snort

STATUS_SUCCESS = "Success"
STATUS_FAILED = "Failed"
MAX_THREADS = 3

class Runner(object):
    """
    Class to prepare the server for 
        1. Uploading snort rules
        2. Uploading pcap files
        
        3. Instructions to perform rule performance checks
        4. Instructions to perform rule alert checks
    """
    def __init__(self):
            pass

    def duration(self, start: datetime, end:Optional[datetime]=None):
        """
        Returns duration in seconds since supplied time
        
        :param start: datetime object
        :param end: Optional[datetime], None = now
        :returns: seconds as decimal since start
        """
        if not end:
            end = datetime.now()
        
        duration = end - start
        return (duration.microseconds + (duration.seconds + duration.days * 24 * 3600) * 1000000) \
            / 1000000.0
    
    def _is_pcap(self, pcap) -> bool:
        """
        Test if file header of supplied file is pcap
        :param pcap: a pcap file
        """
        with open(pcap, 'rb') as f:
            header = f.read(4)
            # Check for both little/big endians
            if header == b"\xa1\xb2\xc3\xd4" or \
               header == b"\xd4\xc3\xb2\xa1":
                return True
            return False

    def _run_snort_alerts(self, runner: Snort, pcap, rules: List[str]=None):
        """
        Run Snort on the supplied pcap and rules
        :param runner: A snort runner instance
        :param pcap: a pcap file
        """
        run = {
                'ruleset': runner.conf.get('ruleset', 'default'),
                'status': STATUS_FAILED
            }
        try:
            run_start = datetime.now()
            if not self._is_pcap(pcap):
                raise Exception("Not a valid pcap file")

            version, alerts = runner.run(pcap, rules)
            run['version'] = version or "Unknown"
            run['status'] = STATUS_SUCCESS
            run['alerts'] = alerts
        except Exception as ex:
            run['error'] = str(ex)
        finally:
            run['duration'] = self.duration(run_start)
        return run

if __name__ == "__main__":
    raise Exception("Not meant for standalone running")