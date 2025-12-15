from pydantic import BaseModel

class BlackListOut(BaseModel):
    timestamp: str
    ip_address: str
    label: str
