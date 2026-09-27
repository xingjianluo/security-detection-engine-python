"""本地快照与流水持久化。

- 快照采用 "临时文件 + fsync + os.replace" 原子替换，失败时原有文件
  保持可用，不残留半成品；
- 流水为 append-only JSONL，每次追加后 flush+fsync，进程崩溃最多丢失
  正在写入的最后一行，且不影响此前行的解析。
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .models import JournalEntry
from .store import Store


def entry_to_dict(entry: JournalEntry) -> dict:
    return {
        "seq": entry.seq,
        "ts": entry.ts.isoformat(),
        "kind": entry.kind,
        "payload": entry.payload,
        "digest": entry.digest,
    }


def entry_from_dict(raw: dict) -> JournalEntry:
    from datetime import datetime

    return JournalEntry(
        seq=int(raw["seq"]),
        ts=datetime.fromisoformat(raw["ts"]),
        kind=raw["kind"],
        payload=raw.get("payload", {}),
        digest=raw.get("digest", ""),
    )


def append_journal_file(path: Path, entries: list[JournalEntry]) -> None:
    """追加落盘（fsync）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry_to_dict(entry), ensure_ascii=False,
                                default=str) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def save_snapshot_atomic(path: Path, data: dict) -> None:
    """临时文件 + fsync + 原子 rename；任何阶段失败都不留半成品。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, default=str, indent=1)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        # 写盘失败：清理临时文件，原快照（若存在）原封不动
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def load_snapshot(path: Path) -> dict | None:
    path = Path(path)
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_journal(path: Path) -> list[dict]:
    """读取流水；跳过空行，损坏行抛 SnapshotError 以便显式处理。"""
    from .errors import SnapshotError

    path = Path(path)
    if not path.exists():
        return []
    rows: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SnapshotError(
                    f"corrupt journal at {path}:{line_no}: {exc}"
                ) from exc
    return rows


def export_snapshot(store: Store, path: Path) -> None:
    save_snapshot_atomic(path, store.snapshot())


def rewrite_journal_file(path: Path, entries: list[JournalEntry]) -> None:
    """原子重写流水文件（用于淘汰最旧条目后的头部截断）。

    临时文件 + fsync + os.replace；失败时原文件保持可用，不留半成品。
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for entry in entries:
                fh.write(json.dumps(entry_to_dict(entry), ensure_ascii=False,
                                    default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------- #
# 归档：被淘汰的历史明细（事件/告警/流水）落入本地归档文件
# ---------------------------------------------------------------------- #

def archive_record(record_kind: str, data: dict) -> dict:
    """构造一条归档记录；record_kind ∈ event / alert / journal。"""
    from datetime import datetime, timezone

    return {
        "archived_at": datetime.now(timezone.utc).isoformat(),
        "record_kind": record_kind,
        "data": data,
    }


def append_archive(path: Path, records: list[dict]) -> None:
    """追加归档记录（flush+fsync）。失败抛 ArchiveError，由调用方保证
    不发生任何状态变更（先写归档、后改内存/流水）。"""
    from .errors import ArchiveError

    if not records:
        return
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            for record in records:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise ArchiveError(f"archive write failed at {path}: {exc}") from exc


def read_archive(path: Path) -> list[dict]:
    """读取归档；文件不存在返回空表，损坏行显式抛 ArchiveError。"""
    from .errors import ArchiveError

    path = Path(path)
    if not path.exists():
        return []
    records: list[dict] = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ArchiveError(
                        f"corrupt archive at {path}:{line_no}: {exc}"
                    ) from exc
    except OSError as exc:
        raise ArchiveError(f"archive read failed at {path}: {exc}") from exc
    return records
