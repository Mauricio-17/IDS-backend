import redis
import json
from fastapi import FastAPI, HTTPException
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import functions
import User
import Device
import BlackList
from motor.motor_asyncio import AsyncIOMotorClient
import bcrypt
import uuid
import pymongo
from pymongo import MongoClient

import utils

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

uri = "mongodb://localhost:27017"
py_client = MongoClient(uri)
database = py_client["network_monitor"]
users_collection = database["User"]
devices_collection = database["Device"]
event_collection = database["Event"]
blacklist_collection = database["BlackList"]


@app.get("/numbers/{count}", response_model=List[int])
def get_numbers(count: int):
    return list(range(count))

@app.get("/get-list", response_model=List[BlackList.BlackListOut])
def get_list():
    result = []
    black_list = list(blacklist_collection.find({}))
    if len(black_list) == 0:
        raise HTTPException(status_code=404, detail="No black list found") 
    
    for item in black_list:
        data = {
            "timestamp": item["creation_date"],
            "ip_address": item["ip_address"],
            "label": item["label"]
        }
        result.append(data)
    
    return result
    

@app.get("/logs", response_model=List)
def get_numbers():
    arr = functions.Parser()
    result = arr.process()
    for i in result:
        existing_event = event_collection.find_one({"flow_id": i["Flow id"]})
        if existing_event:
            continue
        
        existing_device = devices_collection.find_one({"ip_address": i["src ip"]})
        if existing_device:
            existing_user = users_collection.find_one({"id": existing_device["user_id"]})
            if existing_user:
                i["origin_device"] = existing_user["fullname"]
        
        existing_banned = blacklist_collection.find_one({"ip_address": i["dst ip"]})
        
        if existing_banned == None and i["Label"] != "BENIGN":
            banned = {
                "ip_address": i["dst ip"],
                "label": i["Label"],
                "creation_date": i["timestamp"]
            }
            blacklist_collection.insert_one(banned)
  
        event_collection.insert_one(i)
    
    event_list = []
    events = list(event_collection.find({}))
    for i in events:
        del i["_id"]
        event_list.append(i)
    sort = sorted(event_list, key=lambda x: x["timestamp"], reverse=True)
    return sort

@app.post("/save-user", response_model=User.UserOut)
def save_user(user: User.UserCreate):
    # Check if username exists
    if not utils.is_valid_password(user.password):
        raise HTTPException(status_code=400, detail="La contraseña no cumple con al menos 8 dígitos")
    
    existing_user = users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=404, detail="User already exists")

    # Hash password
    hashed_pw = bcrypt.hashpw(user.password.encode("utf-8"), bcrypt.gensalt())

    # Create new user document
    user_id = str(uuid.uuid4())
    new_user = {
        "id": user_id,
        "fullname": user.fullname,
        "area": user.area,
        "username": user.username,
        "password": hashed_pw.decode("utf-8")
    }

    users_collection.insert_one(new_user)

    # Return without password
    return {
        "id": user_id,
        "fullname": user.fullname,
        "area": user.area,
        "username": user.username
    }
    
@app.post("/save-device", response_model=Device.DeviceOut)
def save_device(device: Device.DeviceCreate):
    # Check if username exists
    
    existing_user= users_collection.find_one({"id": device.user_id})
    if existing_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    existing_device = devices_collection.find_one({"ip_address": device.ip_address})
    if existing_device:
        raise HTTPException(status_code=400, detail="IP address already exists")
    
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
    
    devices_collection.insert_one(new_device)
    
    return {
        "id": device_id,
        "user_id": device.user_id,
        "cpu_name": device.cpu_name,
        "ram_storage": device.ram_storage,
        "ip_address": device.ip_address,
        "storage": device.storage
    }
    
    
@app.post("/sign-in", response_model=User.UserOut)
def sign_in(auth: User.Auth):
    # Check if username exists
    existing_user = users_collection.find_one({"username": auth.username})
    
    if existing_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    stored_password = str(existing_user["password"])
    stored_password = stored_password.encode("utf-8")
    print(stored_password)
    if bcrypt.checkpw(auth.password.encode("utf-8"), stored_password):
        return {
            "id": existing_user["id"],
            "fullname": existing_user["fullname"],
            "area": existing_user["area"],
            "username": existing_user["username"]
        }

@app.get("/get-users", response_model=List[User.UserOut])
def get_users():
    
    result = []
    users = list(users_collection.find({}))
    if len(users) == 0:
        raise HTTPException(status_code=404, detail="Users not found") 
    for item in users:
        data = {
            "id": item["id"],
            "fullname": item["fullname"],
            "area": item["area"],
            "username": item["username"]
        }
        result.append(data)
    
    return result

@app.get("/get-devices", response_model=List[Device.DeviceOut])
def get_devices():
    
    result = []
    devices = list(devices_collection.find({}))
    if len(devices) == 0:
        raise HTTPException(status_code=404, detail="Devices not found") 
    for item in devices:
        data = {
            "id": item["id"],
            "user_id": item["user_id"],
            "cpu_name": item["cpu_name"],
            "ram_storage": item["ram_storage"],
            "ip_address": item["ip_address"],
            "storage": item["storage"]
        }
        result.append(data)
    
    return result

