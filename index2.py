from fastapi import FastAPI, HTTPException, APIRouter, Body, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
#from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
import secrets
import os


app = FastAPI()

# MongoDB connection
mongodb_uri = 'mongodb+srv://raghugaikwad8641:Raghugaikwad8@userinfo.d4n8sns.mongodb.net/?retryWrites=true&w=majority'
port = 8000
client = MongoClient(mongodb_uri, port)
db = client.get_database('mydatabase')
user_collection = db.user

# API router
user_router = APIRouter()


class User(BaseModel):
    email: EmailStr
    password: str
    #session_token: str = ""


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserLogout(BaseModel):
    session_token: str


# Route for creating a new user
@user_router.post("/users")
async def create_user(user: User = Body(...)):
    # Check if the user already exists in the database
    existing_user = user_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    # Validate password
    if not any(char.isdigit() for char in user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")
    if not any(char.isupper() for char in user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    session_token = secrets.token_hex(16)  # Generate a session token
    user_dict = user.dict()
    user_dict["session_token"] = session_token
    result = user_collection.insert_one(user_dict)
    return {"id": str(result.inserted_id)}


# Route for user login
@user_router.post("/login")
async def login_user(user: UserLogin = Body(...)):
    # Check if the user exists in the database
    existing_user = user_collection.find_one({"email": user.email})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    if existing_user["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid password")
    session_token = secrets.token_hex(16)  # Generate a new session token
    token_expiration = datetime.now(timezone.utc) + timedelta(minutes=10)

    # Update user's session token and token expiration time in the database
    user_collection.update_one({"email": user.email}, {"$set": {"session_token": session_token, "token_expiration": token_expiration}})
    return {"session_token": session_token}


@user_router.post("/logout")
async def logout_user(
    user_logout: UserLogout,
    response: Response
):
    existing_user = user_collection.find_one({"session_token": user_logout.session_token})
    if not existing_user:
        raise HTTPException(status_code=404, detail="Session not found")

    # Remove the session token and token expiration from the user's document
    user_collection.update_one({"session_token": user_logout.session_token}, {"$set": {"session_token": "", "token_expiration": ""}})

    response.status_code = 200
    return {"message": "Logout successful"}


app.include_router(user_router)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
