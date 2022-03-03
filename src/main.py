import sys
import os
from typing import List
import hashlib
import tempfile

from snort.snort import Snort
from runner import Runner
import schemas 
import config

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse


def get_application():
    conf = {
        'snort' : 'snort',
        'conf' : '/etc/snort/etc/snort.conf',
        'extra_args': '-l /etc/snort/logs'
    }

    snort = Snort(conf)
    runner = Runner()

    app = FastAPI(title=config.PROJECT_NAME,
                  version=config.VERSION)
    return app, snort, runner

app, snort, runner = get_application()


def run_pcap(infile, filename: str, rules: List[schemas.SnortStr]=None) -> dict:
    """
    Helper function for running Snort
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    m = hashlib.md5()
    results = {
                'pcap': filename,
                'status': 'Failed',
              }
    try:
        size=0
        while True:
            buf = infile.read(1024)
            if not buf:
                break
            tmp.write(buf)
            size += len(buf)
            m.update(buf)
        tmp.close()
        results['md5'] = m.hexdigest()
        results['filesize'] = size
        if not rules:
            rules = ["alert icmp any any <> any any (msg: 'Pinging BOTH SIDE'; sid:1; )", "alert icmp any any -> 8.8.8.8 any (msg: 'Pinging to'; sid:2;)"]
        results.update(runner._run_snort_alerts(snort, pcap=tmp.name, rules=rules))
    except OSError as ex:
        results['stderr'] = str(ex)
    finally:
        os.remove(tmp.name)
    return results

@app.get("/api/health", name="websnort:health")
async def health(request: Request):
    client_ip = request.client
    result = {
        "msg": "All Good",
        "status": True,
        "client_ip": client_ip[0],
        "client_port": client_ip[1]
    }
    return result


@app.post("/runpcap/", response_model=schemas.RunPcap)
async def run_pcap_rules(file: UploadFile,
                   rules: List[schemas.SnortStr] = None
                  ):
    """
    Endpoint for generating snort rule alerts and rule profiles
    :param file: The supplied pcap file
    :param rules: The supplied list of valid snort rules
    """  
    result = {
        "pcap": file.filename
    }
    result.update(run_pcap(filename=file.filename, infile=file.file, rules=rules))
    
    return result

@app.post("/ruleperformance/", response_model=schemas.RulePerforance)
async def run_rule_performance(file: UploadFile,
                           rules: List[schemas.SnortStr] = None
                           ):
    """
    Endpoint for generating snort rule performance profiles
    :param file: The supplied pcap file
    :param rules: The supplied list of valid snort rules
    """  
    result = {
        "pcap": file.filename,
        "rules": rules
    }
    result.update(run_pcap(filename=file.filename, infile=file.file, rules=rules))
    
    return result

@app.get("/")
async def main():
    content = """
<body>
<form action="/files/" enctype="multipart/form-data" method="post">
    <input name="files" type="file" multiple>
    <input type="submit">
</form>
</body>
    """
    return HTMLResponse(content=content)