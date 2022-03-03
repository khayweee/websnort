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
    r = requests.post(url, files=file)

    return r.json()

def test_health():
    url = f'{url}/api/health'
    HEADER = {'Content-Type': "application/json"}
    r = requests.get(url, headers=HEADER)
    return r.json()

if __name__ == "__main__":
    if sys.argv[1] == 'health':
        print(test_health())
    elif sys.argv[1] == 'runpcap':
        print(test_run_pcap())
    else:
        print('Idk')

