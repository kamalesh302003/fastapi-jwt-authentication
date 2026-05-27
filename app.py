from fastapi import FastAPI,Depends,HTTPException,Request,Response
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from starlette.middleware.sessions import SessionMiddleware
from jose import jwt,JWTError
from passlib.context import CryptContext
from datetime import datetime,timedelta

app=FastAPI()

# Add Session Middleware
app.add_middleware(SessionMiddleware, secret_key="your-secret-key-for-sessions")

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
    if username !=fake_user["username"]:
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
    return {"message":"JWT Authentication implementing Cookies and Sessions using FastAPI"}

#Login API with Session and Cookie
@app.post("/login")
def login(request: Request,form_data:OAuth2PasswordRequestForm=Depends()):
    user=authenticate_user(form_data.username,form_data.password)
    if not user:
        raise HTTPException(status_code=401,detail="Invalid Username or Password")
    
    # Create JWT Token
    access_token=create_access_token(
        data={"sub":form_data.username}
    )
    
    # Create Session
    request.session["username"]=form_data.username
    request.session["logged_in"]=True
    request.session["login_time"]=datetime.utcnow().isoformat()
    return{
        "message":"Login successful",
        "access_token":access_token,
        "token_type":"bearer",
        "username":form_data.username
    }

#Protected Route using Session
@app.get("/profile")
def profile(request: Request):
    # Check if user is logged in via session
    if "username" not in request.session:
        raise HTTPException(status_code=401,detail="Not authenticated. Please login first")
    
    username = request.session.get("username")
    login_time = request.session.get("login_time")
    
    return{
        "message":"Protected Route Accessed via Session",
        "username": username,
        "login_time": login_time,
        "session_data": dict(request.session)
    }

#Protected Route using JWT Token
@app.get("/profile-jwt")
def profile_jwt(token:str=Depends(oauth2_scheme)):
    try:
        payload=jwt.decode(token,SECRET_KEY,algorithms=[ALGORITHM])
        username=payload.get("sub")
        return{
            "message":"Protected Route Accessed via JWT",
            "username":username
        }
    except JWTError:
        raise HTTPException(status_code=401,detail="Invalid Token")

#Logout Route
@app.post("/logout")
def logout(request:Request):
    request.session.clear()
    return {
        "message":"Logged out successfully.Session cleared.",
        "status":"success"
    }

#Check Session Route
@app.get("/session-info")
def session_info(request:Request):
    if "username" not in request.session:
        return {
            "logged_in":False,
            "message":"No active session"
        }
    return{
        "logged_in":True,
        "username":request.session.get("username"),
        "login_time":request.session.get("login_time"),
        "all_session_data":dict(request.session)
    }