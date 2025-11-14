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

import pymongo
from pymongo import MongoClient

# --- Hashing a password ---
password = b"1q2w3e4r"  # Must be bytes
salt = bcrypt.gensalt()         # Generates a new salt
hashed = bcrypt.hashpw(password, salt)

print("Hashed password:", hashed)

# --- Verifying a password ---
entered_password = b"1q2w3e4r"

if bcrypt.checkpw(entered_password, hashed):
    print("✅ Password match")
else:
    print("❌ Invalid password")

unique_id = uuid.uuid4()

print(unique_id)
print(type(str(unique_id)))

uri = "mongodb://localhost:27017"
py_client = MongoClient(uri)
database = py_client["network_monitor"]
collection = database["Device"]

client = AsyncIOMotorClient("mongodb://localhost:27017")
db = client["network_monitor"]
users_collection = db["User"]
devices_collection = db["Device"]

def get_numbers():
    devices = list(collection.find({}))
    for item in devices:
        print(item)

get_numbers()