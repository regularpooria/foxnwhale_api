from urllib.parse import urlparse
from pymongo import MongoClient
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List
from jwttoken import create_access_token
from fastapi.security import OAuth2PasswordRequestForm
from dotenv import load_dotenv
from PIL import Image
from PIL.ExifTags import TAGS
from fastapi.staticfiles import StaticFiles
from datetime import datetime
from fastapi.responses import FileResponse
import os
import sys
from io import BytesIO
from pydantic import BaseModel
from bson import ObjectId
from pywebpush import webpush, WebPushException
import json
import uuid

load_dotenv()

if os.getenv("MONGODB_PASSWORD") == None:
    print("'MONGODB_PASSWORD' was not found in .env")
    sys.exit()

mongodb_uri = f"mongodb+srv://pooria:{os.getenv('MONGODB_PASSWORD')}@foxnwhale.9i9ytn8.mongodb.net/"
client = MongoClient(mongodb_uri)
db = client["foxnwhale"]

app = FastAPI()

IMAGE_UPLOAD_DIR = "uploads/images"
VOICE_UPLOAD_DIR = "uploads/voices"
os.makedirs("uploads", exist_ok=True)
os.makedirs(IMAGE_UPLOAD_DIR, exist_ok=True)
os.makedirs(VOICE_UPLOAD_DIR, exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


VAPID_PUBLIC_KEY = "BPnMQNKDuRdnZuxo8VEZHdCxV1kR0dZaZZ7CzhqJcbYC0wLdkqak7H96J8ZM9ip9FcXB9KgR8CbMLFOksQ3uxy8"
VAPID_PRIVATE_KEY = "-tM5-qj9uSICIbdQ7xX6ZAiEpugu-bOJyF8B86ps1CQ"


def get_taken_date(file_path: str):
    try:
        image = Image.open(file_path)
        exif_data = image._getexif()
        if exif_data is not None:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "DateTimeOriginal":
                    return datetime.strptime(value, "%Y:%m:%d %H:%M:%S")
    except Exception as e:
        print(f"EXIF error: {e}")
    return None


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for subscriptions
subscriptions = {}


class Subscription(BaseModel):
    subscription: dict


class Notification(BaseModel):
    title: str
    message: str
    target: str


async def auth(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
        )
    token = auth_header.replace("Bearer ", "")
    user = db["users"].find_one({"token": token})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    return user  # contains _id, username, etc.


@app.post("/subscribe")
async def subscribe(sub: Subscription, user=Depends(auth)):
    db["users"].update_one(
        {
            "username": user["username"]
        },
        {
            "$set": {"subscription": sub.subscription}
        }
    )
    return {"success": True}


def get_audience(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    return f"{parsed.scheme}://{parsed.netloc}"


@app.post("/send")
async def send_notification(notif: Notification, user=Depends(auth)):
    target_user = db["users"].find_one({"username": notif.target})
    if not target_user:
        raise HTTPException(404, "Target not found")

    if not target_user["subscription"]:
        raise HTTPException(404, "Subscription not found")

    payload = json.dumps({
        "title": notif.title,
        "body": notif.message,
    })
    try:
        webpush(
            target_user["subscription"],
            payload,
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={
                "sub": "mailto:pooria@pooria.dev",
                "aud": get_audience(target_user["subscription"]["endpoint"]),

            }
        )
        return {"success": True}
    except WebPushException as ex:
        raise ex
        return {"error": str(ex)}


@app.post('/login')
async def login(request: OAuth2PasswordRequestForm = Depends()):
    user = db["users"].find_one({"username": request.username})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    if request.password != user["password"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    access_token = create_access_token(data={"sub": user["username"]})
    db["users"].update_one(
        {
            "username": user["username"]
        },
        {
            "$set": {"token": access_token}
        }
    )
    return {"access_token": access_token, "token_type": "bearer"}


class UserOut(BaseModel):
    username: str
    token: str


class TokenInput(BaseModel):
    token: str


@app.post("/user", response_model=UserOut)
async def login(user=Depends(auth)):
    return UserOut(**user)


@app.get("/")
async def read_root():
    return {
        "hello": "world"
    }


@app.post("/pictures/")
async def upload_picture(user=Depends(auth), files: List[UploadFile] = File(...)):
    results = []
    for file in files:
        if not file.content_type.startswith("image/"):
            continue  # skip non-image files

        # Read file into memory
        contents = await file.read()
        try:
            image = Image.open(BytesIO(contents))
        except Exception as e:
            continue  # skip invalid images
        filename = f"{datetime.utcnow().timestamp()}_{file.filename}"
        file_path = os.path.join(IMAGE_UPLOAD_DIR, filename)

        # Save compressed image
        image.convert("RGB").save(
            file_path, format="JPEG", quality=85, optimize=True)

        taken_date = get_taken_date(file_path)
        uploaded_date = datetime.utcnow()

        result = db["pictures"].insert_one({
            "user_id": ObjectId(user["_id"]),
            "file_path": file_path,
            "uploaded_at": uploaded_date,
            "taken_at": taken_date
        })

        results.append({
            "picture_id": str(result.inserted_id),
            "uploaded_at": uploaded_date.isoformat(),
            "taken_at": taken_date.isoformat() if taken_date else None,
            "path": file_path
        })

    if not results:
        raise HTTPException(
            status_code=400, detail="No valid image files uploaded.")

    return JSONResponse(content={"uploaded": results})


@app.get("/pictures/")
async def list_pictures(user=Depends(auth)):
    pictures = db["pictures"].find({})
    paths = [pic["file_path"] for pic in pictures if "file_path" in pic]
    return JSONResponse(content={"paths": paths})


@app.post("/voice/upload")
async def upload_voice(
    target: str,
    file: UploadFile = File(...),
    user=Depends(auth)
):
    target = db["users"].find_one({"username": target})
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found.")

    filename = f"{uuid.uuid4()}.webm"
    filepath = os.path.join(VOICE_UPLOAD_DIR, filename)
    with open(filepath, "wb") as buffer:
        buffer.write(await file.read())

    db["voices"].insert_one({
        "path": filepath,
        "from": user["_id"],
        "to": target["_id"],
        "seen": False,
        "uploaded_at": datetime.utcnow().isoformat()
    })

    return {"message": "Voice uploaded"}


# Unseen voice messages
@app.get("/voice/unseen")
def get_unseen_voices(user=Depends(auth)):
    unseen = db["voices"].find({"to": user["_id"], "seen": False})
    return [str(v["_id"]) for v in unseen]


@app.get("/voice/get/{voice_id}")
def get_voice(voice_id: str, user=Depends(auth)):
    voice = db["voices"].find_one({"_id": ObjectId(voice_id)})
    if not voice:
        raise HTTPException(
            status_code=404, detail="Voice message not found or unauthorized.")

    db["voices"].update_one({"_id": ObjectId(voice_id)}, {
                            "$set": {"seen": True}})
    return FileResponse(
        voice["path"],
        media_type="audio/mpeg",
        filename=os.path.basename(voice["path"])
    )
