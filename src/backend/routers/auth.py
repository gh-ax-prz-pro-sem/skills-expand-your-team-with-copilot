"""
Authentication endpoints for the High School Management System API
"""

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Dict, Any, Annotated
from pydantic import BaseModel
from datetime import datetime, timedelta
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import jwt

from ..database import teachers_collection

router = APIRouter(
    prefix="/auth",
    tags=["auth"]
)

# Configuration for JWT
SECRET_KEY = "your-secret-key-here-change-in-production"  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

# Password hasher
ph = PasswordHasher()

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    username: str
    display_name: str
    role: str

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash using Argon2"""
    try:
        ph.verify(hashed_password, plain_password)
        return True
    except VerifyMismatchError:
        return False

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """Dependency to get the current authenticated user from JWT token"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.InvalidTokenError:
        raise credentials_exception
    
    teacher = teachers_collection.find_one({"_id": token_data.username})
    if teacher is None:
        raise credentials_exception
    
    return User(
        username=teacher["username"],
        display_name=teacher["display_name"],
        role=teacher["role"]
    )

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """OAuth2 compatible token login endpoint - returns JWT token"""
    teacher = teachers_collection.find_one({"_id": form_data.username})
    
    if not teacher or not verify_password(form_data.password, teacher["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": teacher["username"]}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

@router.get("/me", response_model=User)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    """Get current authenticated user information"""
    return current_user