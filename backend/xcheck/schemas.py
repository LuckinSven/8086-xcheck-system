from datetime import datetime

from pydantic import BaseModel, ConfigDict


class TaskSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    input_type: str
    original_filename: str | None
    current_step: str
    raw_count: int
    valid_count: int
    unique_count: int
    whitelist_removed_count: int
    threatbook_ready_count: int
    malicious_count: int
    high_confidence_count: int
    failed_count: int
    created_at: datetime
