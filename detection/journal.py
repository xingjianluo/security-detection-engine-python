"""Append-only, fsynced JSON-lines decision journal for durable replay."""

from __future__ import annotations

import json
import os
import threading

from detection.models import Decision


def encode_decision(d: Decision) -> str:
    return json.dumps({
        "seq": d.seq,
        "event_id": d.event_id,
        "input_digest": d.input_digest,
        "rule_id": d.rule_id,
        "rule_revision": d.rule_revision,
        "rule_signature": d.rule_signature,
        "matched": d.matched,
        "reason": d.reason,
        "alert_id": d.alert_id,
        "at": d.at,
    }, ensure_ascii=False)


def decode_decision(line: str) -> Decision:
    row = json.loads(line)
    return Decision(
        seq=row["seq"],
        event_id=row["event_id"],
        input_digest=row["input_digest"],
        rule_id=row["rule_id"],
        rule_revision=row["rule_revision"],
        rule_signature=row["rule_signature"],
        matched=row["matched"],
        reason=row["reason"],
        alert_id=row["alert_id"],
        at=row["at"],
    )


class PersistentJournal:
    """Durable append log.

    Each append is flushed and fsynced. The file is opened in append mode and
    kept open for the service lifetime; ``close()`` releases the descriptor.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def append(self, decision: Decision) -> None:
        line = encode_decision(decision)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            os.fsync(self._fh.fileno())

    def read_all(self) -> list[Decision]:
        items: list[Decision] = []
        with self._lock:
            self._fh.flush()
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        items.append(decode_decision(line))
        items.sort(key=lambda d: d.seq)
        return items

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()
                self._fh.close()
