from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List
import uvicorn
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import os
import uuid


SECRET_KEY = os.getenv("SECRET_KEY", "your_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30
MONGO_DB_URL = os.getenv("MONGO_DB_URL", "mongodb://localhost:27017")


app = FastAPI()
client = AsyncIOMotorClient(MONGO_DB_URL)
db = client.notes_app


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


class User(BaseModel):
    user_id: str
    user_name: str
    user_email: EmailStr
    mobile_number: str
    password: str
    last_update: datetime
    created_on: datetime

class UserCreate(BaseModel):
    user_name: str
    user_email: EmailStr
    mobile_number: str
    password: str

class NoteBase(BaseModel):
    note_title: str
    note_content: str

class NoteCreate(NoteBase):
    pass

class NoteInDB(NoteBase):
    note_id: str
    user_id: str
    last_update: datetime
    created_on: datetime

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_by_email(email: str):
    return await db.users.find_one({"user_email": email})

async def authenticate_user(email_or_mobile: str, password: str):
    user = await db.users.find_one({"$or": [
        {"user_email": email_or_mobile},
        {"mobile_number": email_or_mobile}
    ]})
    if user and verify_password(password, user["password"]):
        return user
    return False

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        user = await get_user_by_email(email)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@app.post("/users", response_model=User)
async def create_user(user: UserCreate):
    existing_user = await get_user_by_email(user.user_email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists")
    user_id = str(uuid.uuid4())
    hashed_password = hash_password(user.password)
    user_data = {
        "user_id": user_id,
        "user_name": user.user_name,
        "user_email": user.user_email,
        "mobile_number": user.mobile_number,
        "password": hashed_password,
        "last_update": datetime.utcnow(),
        "created_on": datetime.utcnow()
    }
    await db.users.insert_one(user_data)
    return User(**user_data)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    print(form_data.username)
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user["user_email"]})
    refresh_token = create_refresh_token(data={"sub": user["user_email"]})
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.post("/logout")
async def logout():
    return {"message": "Logout successful"}

@app.post("/notes", response_model=NoteInDB)
async def create_note(note: NoteCreate, current_user: User = Depends(get_current_user)):
    note_id = str(uuid.uuid4())
    note_data = {
        "note_id": note_id,
        "note_title": note.note_title,
        "note_content": note.note_content,
        "user_id": current_user["user_id"],
        "last_update": datetime.utcnow(),
        "created_on": datetime.utcnow()
    }
    await db.notes.insert_one(note_data)
    return NoteInDB(**note_data)

@app.get("/notes", response_model=List[NoteInDB])
async def get_notes(current_user: User = Depends(get_current_user)):
    notes_cursor = db.notes.find({"user_id": current_user["user_id"]})
    notes = await notes_cursor.to_list(length=100)
    return [NoteInDB(**note) for note in notes]

@app.get("/notes/{note_id}", response_model=NoteInDB)
async def get_note(note_id: str, current_user: User = Depends(get_current_user)):
    note = await db.notes.find_one({"note_id": note_id, "user_id": current_user["user_id"]})
    if not note:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return NoteInDB(**note)

@app.put("/notes/{note_id}", response_model=NoteInDB)
async def update_note(note_id: str, note: NoteCreate, current_user: User = Depends(get_current_user)):
    updated_note = {
        "note_title": note.note_title,
        "note_content": note.note_content,
        "last_update": datetime.utcnow()
    }
    result = await db.notes.update_one(
        {"note_id": note_id, "user_id": current_user["user_id"]},
        {"$set": updated_note}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found or not updated")
    data = {**updated_note, "note_id": note_id, "user_id": current_user["user_id"], "created_on": datetime.utcnow()}
    return NoteInDB(**data)

@app.delete("/notes/{note_id}")
async def delete_note(note_id: str, current_user: User = Depends(get_current_user)):
    result = await db.notes.delete_one({"note_id": note_id, "user_id": current_user["user_id"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return {"message": "Note deleted successfully"}

if "__main__" == __name__:
    port = 5000
    print(f"Server listening on PORT: {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)