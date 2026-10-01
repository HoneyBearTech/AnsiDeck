from datetime import datetime

from pydantic import BaseModel


class WorkerOut(BaseModel):
    id: str
    slots: int
    running: int
    online: bool
    first_seen_at: datetime
    last_seen_at: datetime
