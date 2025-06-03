from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from supabase import create_client
import uuid
import secrets
import string
from passlib.context import CryptContext

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Authentication API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, change this to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Supabase client
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")
supabase = create_client(supabase_url, supabase_key)

# Configure password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configure JWT
SECRET_KEY = os.getenv("SECRET_KEY", "YOUR_SECRET_KEY")  # Use a strong secret key in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Configure OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TokenData(BaseModel):
    email: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class PasswordReset(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    token: str
    new_password: str

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except jwt.PyJWTError:
        raise credentials_exception
    
    # Get user from database
    response = supabase.table("users").select("*").eq("email", token_data.email).execute()
    user = response.data[0] if len(response.data) > 0 else None
    
    if user is None:
        raise credentials_exception
    return user

# API Routes
@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    # Check if email already exists
    response = supabase.table("users").select("*").eq("email", user.email).execute()
    if len(response.data) > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Hash the password
    hashed_password = get_password_hash(user.password)
    
    # Create new user in database
    new_user = {
        "id": str(uuid.uuid4()),
        "email": user.email,
        "password": hashed_password,
        "full_name": user.full_name,
        "created_at": datetime.utcnow().isoformat()
    }
    
    try:
        response = supabase.table("users").insert(new_user).execute()
        return {"message": "User registered successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register user: {str(e)}"
        )

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Find user in database
    response = supabase.table("users").select("*").eq("email", form_data.username).execute()
    user = response.data[0] if len(response.data) > 0 else None
    
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Find user in database
    response = supabase.table("users").select("*").eq("email", form_data.username).execute()
    user = response.data[0] if len(response.data) > 0 else None
    
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/forgot-password")
async def forgot_password(password_reset: PasswordReset):
    # Check if user exists
    response = supabase.table("users").select("*").eq("email", password_reset.email).execute()
    if len(response.data) == 0:
        # Don't reveal if email exists or not for security reasons
        return {"message": "If your email is registered, you will receive a password reset link"}
    
    # Generate reset token
    reset_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    expiry = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    
    # Store token in database
    try:
        # First delete any existing reset tokens for this user
        supabase.table("password_resets").delete().eq("email", password_reset.email).execute()
        
        # Then insert new token
        supabase.table("password_resets").insert({
            "email": password_reset.email,
            "token": reset_token,
            "expires_at": expiry
        }).execute()
        
        # In a real app, you would send an email with the reset link
        # For now, just return the token
        return {"message": "Password reset link sent", "token": reset_token}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process password reset: {str(e)}"
        )

@app.post("/reset-password")
async def reset_password(reset_data: ResetPassword):
    # Validate token
    response = supabase.table("password_resets").select("*").eq("token", reset_data.token).execute()
    if len(response.data) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )
    
    reset_info = response.data[0]
    if datetime.fromisoformat(reset_info["expires_at"]) < datetime.utcnow():
        # Delete expired token
        supabase.table("password_resets").delete().eq("token", reset_data.token).execute()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token expired"
        )
    
    # Update user password
    try:
        hashed_password = get_password_hash(reset_data.new_password)
        supabase.table("users").update({"password": hashed_password}).eq("email", reset_info["email"]).execute()
        
        # Delete used token
        supabase.table("password_resets").delete().eq("token", reset_data.token).execute()
        
        return {"message": "Password reset successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reset password: {str(e)}"
        )

@app.get("/me", status_code=status.HTTP_200_OK)
async def read_users_me(current_user = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "full_name": current_user["full_name"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
