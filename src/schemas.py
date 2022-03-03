
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

SnortStr = str

class RunPcap(BaseModel):
    status: str
    pcap: str
    md5: str
    filesize: float
    profiles: List[dict]
    alerts: List[dict]
    version: str
    error: Optional[str]
    duration: float

class RulePerforance(BaseModel):
    status: str
    pcap: str
    md5: str
    filesize: float
    rules: List[SnortStr]
    profiles: List[dict]
    version: str
    error: Optional[str]
    duration: float
