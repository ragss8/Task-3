from fastapi import FastAPI, HTTPException, APIRouter, Body , Depends
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta

app = FastAPI()

# MongoDB connection
mongodb_uri ='mongodb+srv://raghugaikwad8641:Raghugaikwad8@userinfo.d4n8sns.mongodb.net/?retryWrites=true&w=majority'
port = 8000
client = MongoClient(mongodb_uri, port)
db = client.get_database('mydatabase')
user_collection = db.user

# API router
user_router = APIRouter()

class User(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    access_token: str
    token_expiration: datetime

class UserLogout(BaseModel):
    email: EmailStr
    access_token: str

# Route for creating a new user
@user_router.post("/users")
async def create_user(user: User = Body(...)):
    print(user)
    # Check if the user already exists in the database
    existing_user = user_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    # Validate password
    if not any(char.isdigit() for char in user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit")
    if not any(char.isupper() for char in user.password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter")
    user_dict = user.dict()
    result = user_collection.insert_one(user_dict)
    return {"id": str(result.inserted_id)}

# Route for user login
@user_router.post("/login")
async def login_user(user: User = Body(...)):
    # Check if the user exists in the database
    existing_user = user_collection.find_one({"email": user.email})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    # Check if the provided password is correct
    if existing_user["password"] != user.password:
        raise HTTPException(status_code=401, detail="Invalid password")
    access_token = str(datetime.utcnow()) + user.email
    token_expiration = datetime.utcnow() + timedelta(minutes=30)

    # Update user's access token and token expiration time in the database
    user_collection.update_one({"email": user.email}, {"$set": {"access_token": access_token, "token_expiration": token_expiration}})

    return {"access_token": access_token}


@user_router.post("/logout")
async def logout_user(user_logout: UserLogout, token: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    # Check if the user exists in the database
    existing_user = user_collection.find_one({"email": user_logout.email})
    if not existing_user:
        raise HTTPException(status_code=404, detail="User not found")
    if existing_user["access_token"] != token.credentials:
        raise HTTPException(status_code=401, detail="Invalid access token")
    user_collection.update_one({"email": user_logout.email}, {"$unset": {"access_token": "", "token_expiration": ""}})

    return {"message": "Logout successful"}


# Include router in app
app.include_router(user_router)

# Add CORS middleware to allow requests from all origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
) 

