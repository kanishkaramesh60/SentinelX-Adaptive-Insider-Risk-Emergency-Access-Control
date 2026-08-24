from fastapi import FastAPI, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import Base, engine, get_db
from .models import SecurityEvent


Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="Adaptive Insider Threat Detection System",
    version="1.0"
)


class Event(BaseModel):

    device_id: str
    username: str
    event_type: str
    action: str
    resource: str
    source_ip: str
    timestamp: str
    risk_score: float = 0


@app.get("/")
def home():

    return {
        "message": "Insider Threat Detection Server Running"
    }


@app.post("/events")
def create_event(
    event: Event,
    db: Session = Depends(get_db)
):

    new_event = SecurityEvent(

        device_id=event.device_id,

        username=event.username,

        event_type=event.event_type,

        action=event.action,

        resource=event.resource,

        source_ip=event.source_ip,

        timestamp=event.timestamp,

        risk_score=event.risk_score
    )

    db.add(new_event)

    db.commit()

    db.refresh(new_event)


    return {

        "message": "Event stored successfully",

        "event_id": new_event.id

    }


@app.get("/events")
def get_events(
    db: Session = Depends(get_db)
):

    events = db.query(SecurityEvent).all()

    result = []

    for event in events:

        result.append({

            "id": event.id,

            "device_id": event.device_id,

            "username": event.username,

            "event_type": event.event_type,

            "action": event.action,

            "resource": event.resource,

            "source_ip": event.source_ip,

            "timestamp": event.timestamp,

            "risk_score": event.risk_score

        })

    return result