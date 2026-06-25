from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class QueueJob:
    id: str
    kind: str
    payload: dict[str, Any]
    run_after: datetime
    attempts: int = 0

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        payload: dict[str, Any],
        run_after: datetime,
    ) -> QueueJob:
        return cls(
            id=uuid.uuid4().hex,
            kind=kind,
            payload=payload,
            run_after=run_after,
        )

    @classmethod
    def from_json(cls, value: dict[str, Any]) -> QueueJob:
        return cls(
            id=str(value["id"]),
            kind=str(value["kind"]),
            payload=dict(value["payload"]),
            run_after=_parse_datetime(str(value["run_after"])),
            attempts=int(value.get("attempts", 0)),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "payload": self.payload,
            "run_after": self.run_after.astimezone(UTC).isoformat(),
            "attempts": self.attempts,
        }

    def rescheduled(self, run_after: datetime) -> QueueJob:
        return QueueJob(
            id=self.id,
            kind=self.kind,
            payload=self.payload,
            run_after=run_after,
            attempts=self.attempts + 1,
        )


class StateStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.state_path = directory / "state.json"
        self.queue_path = directory / "queue.json"
        self.events_path = directory / "queue_events.jsonl"

    def load_state(self) -> dict[str, Any]:
        return self._read_json_object(self.state_path)

    def update_state(self, values: dict[str, Any]) -> None:
        state = self.load_state()
        state.update(values)
        self._write_json_object(self.state_path, state)

    def enqueue_job(self, job: QueueJob) -> None:
        jobs = self._load_queue()
        jobs.append(job)
        self._save_queue(jobs)
        self.record_event("enqueue", job.to_json())

    def due_jobs(self, now: datetime | None = None) -> list[QueueJob]:
        now = now or datetime.now(UTC)
        return [job for job in self._load_queue() if job.run_after <= now]

    def complete_job(self, job_id: str) -> None:
        jobs = [job for job in self._load_queue() if job.id != job_id]
        self._save_queue(jobs)
        self.record_event("complete", {"id": job_id})

    def reschedule_job(self, job_id: str, run_after: datetime) -> None:
        jobs = [
            job.rescheduled(run_after) if job.id == job_id else job
            for job in self._load_queue()
        ]
        self._save_queue(jobs)
        self.record_event(
            "reschedule", {"id": job_id, "run_after": run_after.isoformat()}
        )

    def record_event(self, event: str, payload: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        record = {
            "event": event,
            "payload": payload,
            "created_at": datetime.now(UTC).isoformat(),
        }
        with self.events_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False, sort_keys=True))
            file.write("\n")

    def failed_account_silence_ids(self) -> list[str]:
        if not self.events_path.exists():
            return []
        account_ids: list[str] = []
        seen: set[str] = set()
        with self.events_path.open(encoding="utf-8") as file:
            for line in file:
                record = json.loads(line)
                if record.get("event") != "account_silence_failed":
                    continue
                payload = record.get("payload") or {}
                account_id = str(payload.get("account_id", ""))
                if not account_id or account_id in seen:
                    continue
                seen.add(account_id)
                account_ids.append(account_id)
        return account_ids

    def _load_queue(self) -> list[QueueJob]:
        return [
            QueueJob.from_json(item) for item in self._read_json_array(self.queue_path)
        ]

    def _save_queue(self, jobs: list[QueueJob]) -> None:
        self._write_json_array(self.queue_path, [job.to_json() for job in jobs])

    def _read_json_object(self, path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with path.open(encoding="utf-8") as file:
            return dict(json.load(file))

    def _read_json_array(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as file:
            return list(json.load(file))

    def _write_json_object(self, path: Path, value: dict[str, Any]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _write_json_array(self, path: Path, value: list[dict[str, Any]]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
