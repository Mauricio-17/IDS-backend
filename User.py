from pydantic import BaseModel

class UserCreate(BaseModel):
    full_name: str
    area: str
    username: str
    password: str
    

class UserOut(BaseModel):
    id: str
    full_name: str
    area: str
    username: str
    
class Auth(BaseModel):
    username: str
    password: str
    