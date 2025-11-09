from pydantic import BaseModel

class DeviceCreate(BaseModel):
    user_id: str
    cpu_name: str
    ram_storage: str
    ip_address: str
    storage: str

class DeviceOut(BaseModel):
    id: str
    user_id: str
    cpu_name: str
    ram_storage: str
    ip_address: str
    storage: str