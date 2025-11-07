import redis
import json
from fastapi import FastAPI
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import functions

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

@app.get("/numbers/{count}", response_model=List[int])
def get_numbers(count: int):
    return list(range(count))

@app.get("/logs", response_model=List[dict])
def get_numbers():
    arr = functions.Parser()
    return arr.process()