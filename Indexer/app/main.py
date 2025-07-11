from fastapi import FastAPI, Depends, Body, Header, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from pydantic import BaseModel
from app.database import SessionLocal
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class EventIn(BaseModel):
    newLines: list[str]

@app.get("/events")
def get_events(api_key_readlogs: str, db: Session = Depends(get_db)):
    result = db.execute(
        text("SELECT id FROM api_key_readlogs WHERE auth_key_readlogs = :token"),
        {"token": api_key_readlogs}
    ).fetchone()
    if not result:
        raise HTTPException(status_code=403, detail="Invalid token")

    result = db.execute(text("SELECT * FROM events"))
    rows = result.fetchall()
    return [{"id": row[0], "log": row[1]} for row in rows]

@app.post("/events")
def insert_events(
    event: EventIn,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header missing")

    result = db.execute(
        text("SELECT id FROM api_key WHERE auth_key = :token"),
        {"token": authorization}
    ).fetchone()
    if not result:
        raise HTTPException(status_code=403, detail="Invalid token")

    for line in event.newLines:
        db.execute(text("INSERT INTO events (log) VALUES (:log)"), {"log": line})
    db.commit()

    return {"message": f"{len(event.newLines)} logs inserted"}
