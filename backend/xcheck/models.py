from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from enum import StrEnum

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class TaskStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_WHITELIST = "waiting_whitelist_confirmation"
    WAITING_THREATBOOK = "waiting_threatbook_confirmation"
    PAUSED_QUOTA = "paused_quota"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    COMPLETED = "completed"


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING = "waiting"
    FAILED = "failed"
    COMPLETED = "completed"
    SKIPPED = "skipped"


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: uuid.uuid4().hex)
    status: Mapped[str] = mapped_column(String(48), default=TaskStatus.QUEUED.value, index=True)
    input_type: Mapped[str] = mapped_column(String(24))
    original_filename: Mapped[str | None] = mapped_column(String(512))
    stored_path: Mapped[str | None] = mapped_column(String(1024))
    manual_text: Mapped[str | None] = mapped_column(Text)
    config_snapshot: Mapped[str] = mapped_column(Text, default="{}")
    current_step: Mapped[str] = mapped_column(String(64), default="save_input")
    raw_count: Mapped[int] = mapped_column(Integer, default=0)
    valid_count: Mapped[int] = mapped_column(Integer, default=0)
    invalid_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_count: Mapped[int] = mapped_column(Integer, default=0)
    whitelist_removed_count: Mapped[int] = mapped_column(Integer, default=0)
    threatbook_ready_count: Mapped[int] = mapped_column(Integer, default=0)
    malicious_count: Mapped[int] = mapped_column(Integer, default=0)
    high_confidence_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    error_summary: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    steps: Mapped[list[TaskStep]] = relationship(back_populates="task", cascade="all, delete-orphan")
    ips: Mapped[list[TaskIP]] = relationship(back_populates="task", cascade="all, delete-orphan")


class TaskStep(Base):
    __tablename__ = "task_steps"
    __table_args__ = (UniqueConstraint("task_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default=StepStatus.PENDING.value)
    progress_current: Mapped[int] = mapped_column(Integer, default=0)
    progress_total: Mapped[int] = mapped_column(Integer, default=0)
    input_count: Mapped[int] = mapped_column(Integer, default=0)
    output_count: Mapped[int] = mapped_column(Integer, default=0)
    current_batch: Mapped[int] = mapped_column(Integer, default=0)
    total_batches: Mapped[int] = mapped_column(Integer, default=0)
    checkpoint: Mapped[str | None] = mapped_column(Text)
    error_summary: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    task: Mapped[Task] = relationship(back_populates="steps")


class TaskIP(Base):
    __tablename__ = "task_ips"
    __table_args__ = (
        UniqueConstraint("task_id", "normalized_ip"),
        Index("ix_task_ips_task_stage", "task_id", "stage"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    raw_value: Mapped[str] = mapped_column(String(256))
    normalized_ip: Mapped[str] = mapped_column(String(64))
    ip_version: Mapped[int] = mapped_column(Integer)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    stage: Mapped[str] = mapped_column(String(48), default="validated", index=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    first_position: Mapped[str | None] = mapped_column(String(128))
    last_position: Mapped[str | None] = mapped_column(String(128))
    sample_positions: Mapped[str] = mapped_column(Text, default="[]")
    invalid_reason: Mapped[str | None] = mapped_column(String(256))
    task: Mapped[Task] = relationship(back_populates="ips")


class InputError(Base):
    __tablename__ = "input_errors"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    raw_value: Mapped[str] = mapped_column(Text)
    position: Mapped[str] = mapped_column(String(256))
    reason: Mapped[str] = mapped_column(String(256))


class WhitelistResult(Base):
    __tablename__ = "whitelist_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_ip_id: Mapped[int] = mapped_column(ForeignKey("task_ips.id", ondelete="CASCADE"), unique=True)
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    result_code: Mapped[str] = mapped_column(String(24), index=True)
    verdict: Mapped[str] = mapped_column(Text, default="")
    matches_json: Mapped[str] = mapped_column(Text, default="[]")
    raw_json: Mapped[str] = mapped_column(Text, default="{}")


class ThreatbookBatch(Base):
    __tablename__ = "threatbook_batches"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: uuid.uuid4().hex)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    batch_number: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    addresses_json: Mapped[str] = mapped_column(Text)
    unresolved_json: Mapped[str] = mapped_column(Text, default="[]")
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    response_code: Mapped[int | None] = mapped_column(Integer)
    response_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ThreatbookResult(Base):
    __tablename__ = "threatbook_results"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_ip_id: Mapped[int] = mapped_column(ForeignKey("task_ips.id", ondelete="CASCADE"), unique=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("threatbook_batches.id", ondelete="CASCADE"), index=True)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    confidence_level: Mapped[str | None] = mapped_column(String(24), index=True)
    severity: Mapped[str | None] = mapped_column(String(24), index=True)
    judgments_json: Mapped[str] = mapped_column(Text, default="[]")
    country: Mapped[str | None] = mapped_column(String(128))
    province: Mapped[str | None] = mapped_column(String(128))
    city: Mapped[str | None] = mapped_column(String(128))
    carrier: Mapped[str | None] = mapped_column(String(256))
    asn_number: Mapped[int | None] = mapped_column(Integer)
    asn_name: Mapped[str | None] = mapped_column(String(256))
    scene: Mapped[str | None] = mapped_column(String(128))
    update_time: Mapped[str | None] = mapped_column(String(64))
    permalink: Mapped[str | None] = mapped_column(String(1024))
    raw_json: Mapped[str] = mapped_column(Text, default="{}")


class StepAttempt(Base):
    __tablename__ = "step_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(ForeignKey("tasks.id", ondelete="CASCADE"), index=True)
    step_name: Mapped[str] = mapped_column(String(64), index=True)
    batch_id: Mapped[str | None] = mapped_column(String(32), index=True)
    attempt_number: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24))
    http_status: Mapped[int | None] = mapped_column(Integer)
    response_code: Mapped[int | None] = mapped_column(Integer)
    safe_request_json: Mapped[str] = mapped_column(Text, default="{}")
    error_type: Mapped[str | None] = mapped_column(String(128))
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DailyUsage(Base):
    __tablename__ = "daily_usage"
    usage_date: Mapped[date] = mapped_column(Date, primary_key=True)
    successful_ips: Mapped[int] = mapped_column(Integer, default=0)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
