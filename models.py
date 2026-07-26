"""
models.py

SQLAlchemy models for the Observable Incident Agent.
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    func,
)

from database import Base


class IncidentRun(Base):
    __tablename__ = "incident_runs"

    id = Column(Integer, primary_key=True, index=True)

    run_id = Column(
        String(128),
        unique=True,
        nullable=False,
        index=True,
    )

    status = Column(
        String(32),
        nullable=False,
        default="waiting",
    )

    request_hash = Column(
        String(64),
        nullable=False,
        index=True,
    )

    request_json = Column(
        Text,
        nullable=False,
    )

    response_json = Column(
        Text,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class ReceiptRecord(Base):
    __tablename__ = "receipt_records"

    id = Column(Integer, primary_key=True, index=True)

    run_id = Column(
        String(128),
        nullable=False,
        index=True,
    )

    receipt_id = Column(
        String(128),
        nullable=False,
        index=True,
    )

    receipt_hash = Column(
        String(64),
        nullable=False,
    )

    response_json = Column(
        Text,
        nullable=False,
    )

    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )