from fastapi import FastAPI,Depends,HTTPException
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from jose import jwt,JWTError
from passlib.context import CryptContext
from datetime import datetime,timedelta

app=FastAPI()

#Secret Key
SECRET_KEY="mysecretkey"

#JWT Algorithm
ALGORITHM="HS256"

#Token Expiry
ACCESS_TOKEN_EXPIRE_MINUTES=30

#Password Hashing
pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")

#OAuth2
oauth2_scheme=OAuth2PasswordBearer(tokenUrl="login")

#Fake Database
fake_user={
    "username":"Kamalesh Chandrasekaran",
    "password":pwd_context.hash("2003")
}

#Verify Password
def verify_password(plain_password,hashed_password):
    return pwd_context.verify(plain_password,hashed_password)

#Authenticate User
def authenticate_user(username,password):
    if username!=fake_user["username"]:
        return False
    if not verify_password(password,fake_user["password"]):
        return False
    return True

#Create JWT Token
def create_access_token(data:dict):
    to_encode=data.copy()
    expire=datetime.utcnow()+timedelta(minutes=30)
    to_encode.update({"exp":expire})
    encoded_jwt=jwt.encode(to_encode,SECRET_KEY,algorithm=ALGORITHM)
    return encoded_jwt

#Home Route
@app.get("/home")
def home():
    return {"message":"Welcome to the FastAPI JWT Authentication"}

#Login API
@app.post("/login")
def login(form_data:OAuth2PasswordRequestForm=Depends()):
    user=authenticate_user(form_data.username,form_data.password)
    if not user:
        raise HTTPException(status_code=401,detail="Invalid Username or Password")
    access_token=create_access_token(
        data={"sub":form_data.username}
    )
    return {
        "access_token":access_token,
        "token_type":"bearer"
    }

# Protected Route
@app.get("/profile")
def profile(token:str=Depends(oauth2_scheme)):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username=payload.get("sub")
        return {
            "message":"Protected Route Accessed",
            "username":username
        }
    except JWTError:
        raise HTTPException(status_code=401,detail="Invalid Token")