
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel

class RunPcap(BaseModel):
    pcap: str
    md5: str
    filesize: float
    status: str
    profiles: List[dict]
    alerts: List[dict]
    error: Optional[str]
    duration: float
    version: str
