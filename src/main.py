from fastapi import FastAPI, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, JSON, select
import os
import uvicorn

from models.user_auth import UserAuth
from models.user_update import UserUpdate

DATABASE_USER = os.environ['POSTGRES_USER']
DATABASE_PASSWORD = os.environ['POSTGRES_PASSWORD']
DATABASE = os.environ['POSTGRES_DB']
DATABASE_URL = f"postgresql+asyncpg://{DATABASE_USER}:{DATABASE_PASSWORD}@db/{DATABASE}"

app = FastAPI()

engine = create_async_engine(DATABASE_URL, echo=True, future=True)
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, autoincrement=True, primary_key=True, index=True)
    login = Column(String)
    password = Column(String)
    details = Column(JSON)

class CurrentSession(Base):
    __tablename__ = 'current_session'
    id = Column(Integer, primary_key=True, index=True)
    login = Column(String, nullable=False)

@app.on_event("startup")
async def startup_event():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.post('/register')
async def register(user_data: UserAuth):
    login = user_data.login
    password = user_data.password

    async with async_session() as session:
        result = await session.execute(select(User).where(User.login == login))
        existing_user = result.scalar_one_or_none()
        if existing_user:
            raise HTTPException(status_code=400, detail="User already exists")

        new_user = User(login=login, password=password)
        session.add(new_user)
        await session.commit()

    return {"message": "User registered"}

@app.post('/authenticate')
async def authenticate(user_data: UserAuth):
    login = user_data.login
    password = user_data.password

    async with async_session() as session:
        result = await session.execute(select(User).where(User.login == login))
        user = result.scalar()
        if not user or user.password != password:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        result = await session.execute(select(CurrentSession))
        current_session = result.scalar()
        if current_session:
            current_session.login = login
        else:
            new_session = CurrentSession(login=login)
            session.add(new_session)
        await session.commit()

    return {"message": "Authentication successful"}


@app.post('/update')
async def update(user_update_data: UserUpdate):
    async with async_session() as session:
        result = await session.execute(select(CurrentSession))
        current_session = result.scalar()
        if not current_session:
            raise HTTPException(status_code=401, detail="Unauthorized")

        result = await session.execute(select(User).where(User.login == current_session.login))
        user = result.scalar()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user_details = user.details or {}
        print(user_details)
        update_data = user_update_data.dict()
        user.details = {**user_details, **update_data}

        await session.commit()

    return {"message": "User data updated"}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=5000)
