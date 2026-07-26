from sqlalchemy import Column, Integer, String, Text, UniqueConstraint
from database import Base

class IncidentRun(Base):
    __tablename__ = "incident_runs"
    run_id = Column(String, primary_key=True, index=True)
    status = Column(String, nullable=False)
    request_json = Column(Text, nullable=False)
    response_json = Column(Text, nullable=False)
    request_hash = Column(String, nullable=True)

class ReceiptRecord(Base):
    __tablename__ = "receipt_records"
    id = Column(Integer, primary_key=True)
    run_id = Column(String, index=True, nullable=False)
    receipt_id = Column(String, nullable=False)
    receipt_hash = Column(String, nullable=False)
    response_json = Column(Text, nullable=False)
    __table_args__ = (UniqueConstraint("run_id", "receipt_id", name="uq_receipt_run_id"),)
