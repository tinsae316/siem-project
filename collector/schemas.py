from pydantic import BaseModel
from typing import Optional, Dict, List

class LogSchema(BaseModel):
    timestamp: str
    event: Dict
    host: Dict
    source: Dict
    user: Optional[Dict] = None
    http: Optional[Dict] = None
    url: Optional[Dict] = None
    user_agent: Optional[Dict] = None
    network: Optional[Dict] = None
    attack: Optional[Dict] = None
    labels: Optional[List[str]] = []
    message: str
