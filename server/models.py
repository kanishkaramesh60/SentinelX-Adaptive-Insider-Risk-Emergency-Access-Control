from sqlalchemy import Column, Integer, String, Float
from .database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    device_id = Column(String)
    username = Column(String)

    event_type = Column(String)
    action = Column(String)

    resource = Column(String)

    source_ip = Column(String)

    timestamp = Column(String)

    risk_score = Column(Float, default=0)