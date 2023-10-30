from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel, ConfigDict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from database import engine, SessionLocal
import models
from typing import List, Optional

SECRET_KEY = "81afc96a90ee3b84c825eeae51ec562bc02573b067c760be48eb1383068f4469"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

models.Base.metadata.create_all(bind=engine)


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


class UserBase(BaseModel):
    name: str
    phone: str
    email: str
    password: str
    model_config = ConfigDict(from_attributes=True)


# class UserCreate(UserBase):

#     Email : str
#     password :  str

class UserLogin(BaseModel):
    email: str
    password: str


# class UserResponse(UserBase):
#     model_config = ConfigDict(from_attributes=True)
#     id: int
#     name :str
#     phone : str
#     email : str
#     password : str


class BlogCreate(BaseModel):
    title: str
    description: str


class BlogResponse(BaseModel):
    id: str
    title: str
    content: str
    owner_id: int


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


# class UserInDB(models.User):
#     hashed_password :str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    user = db.query(UserBase).filter(UserBase.email == username).first()
    return user


def authenticate_user(db: SessionLocal, email: str, password: str):
    user = get_user(db, email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: SessionLocal = Depends(get_db)):
    global token_data
    credential_exception: HTTPException = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                                        detail="could not validate credentials",
                                                        headers={"www-Authenticate ": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception

        token_data = TokenData(username=username)
    except JWTError:
        credential_exception

    user = get_user(db, username=token_data.username)
    if user is None:
        raise credential_exception
    return user


@app.post("/register")
async def register(user: UserBase, db: SessionLocal = Depends(get_db)):
    print(user, "String")
    hashed_password = get_password_hash(user.password)
    db_user = models.User(email=user.email, password=hashed_password)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e:
        print(e)


# @app.post("/login", response_model=Token)
# def login_user(user_data: UserLogin, db: SessionLocal = Depends(get_db)):
#     print(user_data, "String")
#     db_user = db.query(models.User).filter(models.User.email == user_data.email).first()
#     if not db_user or not pwd_context.verify(user_data.password, db_user.password):
#         raise HTTPException(status_code=400, detail="Incorrect email or password")

#     access_token = create_access_token(data={"sub": db_user.email})
#     print(access_token)
#     return {"access_token": access_token, "token_type": "bearer"}


@app.post("/token", response_model=Token)
async def login_for_access_token(user_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    print(user_data, "String")
    db_user = db.query(models.User).filter(models.User.email == user_data.username).first()
    if not db_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password",
                            headers={"www-Authenticate": "Bearer"})

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": db_user.email},
                                       expires_delta=access_token_expires)
    print(access_token)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/blogs", response_model=BlogCreate)
def create_blog(blog: BlogCreate, current_user: str = Depends(get_current_user), db: SessionLocal = Depends(get_db)):
    db_blog = models.Blog(**blog.dict(), owner_id=current_user)
    try:
        db.add(db_blog)
        db.commit()
        db.refresh(db_blog)
        return db_blog
    except Exception as e:
        print(e)


@app.get("/blogs/", response_model=List[BlogResponse])
async def get_blogs(skip: int = 0, limit: int = 10, db: SessionLocal = Depends(get_db)):
    blogs = db.query(models.Blog).offset(skip).limit(limit).all()
    return blogs


@app.put("/blogs/{blog_id}/", response_model=BlogResponse)
async def update_blog(blog_id: int, blog: BlogCreate, current_user: models.User = Depends(get_current_user),
                      db: SessionLocal = Depends(get_db)):
    db_blog = db.query(models.Blog).filter(models.Blog.id == blog_id, models.Blog.owner_id == current_user.id).first()
    if db_blog is None:
        raise HTTPException(status_code=404, detail="Blog not found")
    for key, value in blog.dict().items():
        setattr(db_blog, key, value)
    db.commit()
    db.refresh(db_blog)
    return db_blog


@app.delete("/blogs/{blog_id}/", response_model=BlogResponse)
async def delete_blog(blog_id: int, current_user: models.User = Depends(get_current_user),
                      db: SessionLocal = Depends(get_db)):
    db_blog = db.query(models.Blog).filter(models.Blog.id == blog_id, models.Blog.owner_id == current_user.id).first()
    if db_blog is None:
        raise HTTPException(status_code=404, detail="Blog not found")
    db.delete(db_blog)
    db.commit()
    return db_blog
