import redis
import json
from fastapi import FastAPI, HTTPException
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import functions
import User
import Device
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import uuid

app = FastAPI()

origins = [
    "http://localhost:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client["network_monitor"]
users_collection = db["User"]
devices_collection = db["Device"]


@app.get("/numbers/{count}", response_model=List[int])
def get_numbers(count: int):
    return list(range(count))

@app.get("/logs", response_model=List[dict])
def get_numbers():
    arr = functions.Parser()
    return arr.process()

@app.post("/save-user", response_model=User.UserOut)
async def save_ser(user: User.UserCreate):
    # Check if username exists
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Hash password
    hashed_pw = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    # Create new user document
    user_id = str(uuid.uuid4())
    new_user = {
        "id": user_id,
        "full_name": user.full_name,
        "area": user.area,
        "username": user.username,
        "password": hashed_pw.decode("utf-8")
    }

    await users_collection.insert_one(new_user)

    # Return without password
    return {
        "id": user_id,
        "full_name": user.full_name,
        "area": user.area,
        "username": user.username
    }
    
@app.post("/save-device", response_model=Device.DeviceOut)
async def save_ser(device: Device.DeviceCreate):
    # Check if username exists
    existing_device = await devices_collection.find_one({"ip_address": device.ip_address})
    if existing_device:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create new user document
    device_id = str(uuid.uuid4())
    new_device = {
        "id": device_id,
        "user_id": device.user_id,
        "cpu_name": device.cpu_name,
        "ram_storage": device.ram_storage,
        "ip_address": device.ip_address,
        "storage": device.storage
    }
    
    await devices_collection.insert_one(new_device)
    
    return {
        "id": device_id,
        "user_id": device.user_id,
        "cpu_name": device.cpu_name,
        "ram_storage": device.ram_storage,
        "ip_address": device.ip_address,
        "storage": device.storage
    }
    
    
@app.post("/sign-in", response_model=User.UserOut)
async def sign_in(auth: User.Auth):
    # Check if username exists
    existing_user = await users_collection.find_one({"username": auth.username})
    print(existing_user["username"])    
    
    if existing_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    

    stored_password = str(existing_user["password"])
    stored_password = stored_password.encode("utf-8")
    print(stored_password)
    if bcrypt.checkpw(auth.password.encode("utf-8"), stored_password):
        return {
            "id": existing_user["id"],
            "full_name": existing_user["full_name"],
            "area": existing_user["area"],
            "username": existing_user["username"]
        }
    