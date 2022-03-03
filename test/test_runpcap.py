import requests
import json
import sys

URL = "http://127.0.0.1:80"

def test_run_pcap():
    url = f'{URL}/runpcap'
    HEADER = {'Content-Type': "multipart/form-data"}
    file = {
        'file': open('icmp_8888.pcap', 'rb'),
    }
    data = {
        'rules': 'alert icmp 8.8.8.8 any -> any any (msg: "Test"; sid:1; )'
    }
    r = requests.post(url, files=file, data=data)

    return r.json()


def test_run_rule_performance():
    url = f'{URL}/ruleperformance'
    HEADER = {'Content-Type': "multipart/form-data"}
    file = {
        'file': open('icmp_8888.pcap', 'rb'),
    }
    data = {
        'rules': ['alert icmp 8.8.8.8 any -> any any (msg: "Test"; sid:1; )',
                  'alert icmp 8.8.8.8 any -> any any (msg: "Test2"; sid:1; )']
    }
    r = requests.post(url, files=file, data=data)
    return r.json()

def test_run_rule_performance_no_pcap():
    url = f'{URL}/ruleperformance'
    HEADER = {'Content-Type': "multipart/form-data"}
    data = {
        'rules': ['alert icmp 8.8.8.8 any -> any any (msg: "Test"; sid:1; )']
    }
    r = requests.post(url, data=data)
    return r.json()

def test_health():
    url = f'{URL}/health'
    HEADER = {'Content-Type': "application/json"}
    r = requests.get(url, headers=HEADER)
    return r.json()

if __name__ == "__main__":
    if sys.argv[1] == 'health':
        print(test_health())
    elif sys.argv[1] == 'runpcap':
        print(test_run_pcap())
    elif sys.argv[1] == 'performance':
        print(test_run_rule_performance())
    elif sys.argv[1] == 'performance_nopcap':
        print(test_run_rule_performance_no_pcap())
    else:
        print('Idk')

