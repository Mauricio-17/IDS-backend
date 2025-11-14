from pydantic import BaseModel

class UserCreate(BaseModel):
    fullname: str
    area: str
    username: str
    password: str
    

class UserOut(BaseModel):
    id: str
    fullname: str
    area: str
    username: str
    
class Auth(BaseModel):
    username: str
    password: str
    