from datetime import datetime

from pydantic import BaseModel


class WorkerOut(BaseModel):
    id: str
    slots: int
    isolated: bool | None
    egress_filtered: bool | None
    host_keys: bool | None = None
    # It can limit runs to their inventory's hosts (runs that must wait for such a worker).
    egress_allowlist: bool | None = None
    # It loads SSH certificates (runs with a certificate credential wait for such a worker).
    ssh_certificates: bool | None = None
    running: int
    online: bool
    first_seen_at: datetime
    last_seen_at: datetime
