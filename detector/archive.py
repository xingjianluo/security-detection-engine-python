"""有界保留的本地归档：被淘汰历史明细的长期留存。

设计要点
========
- 归档内容即被淘汰点之前的流水（JSONL 分段），是完整重放的输入；
- 日常查询/运行不加载归档，仅显式重放/重建时读取；
- 分段写入 "临时文件 + fsync + os.replace" 原子落盘，manifest 同样
  原子替换；写失败显式报错且不留半成品，已提交分段不受影响；
- 归档在后台守护线程执行，不阻塞正常摄入；待归档目标队列有界
  （``archive_max_pending``），满时摄入被显式拒绝（archive_backpressure），
  内存不随之膨胀；连续淘汰的水位可合并，分段互不交叠；
- 读取（重放/重建）失败显式抛 :class:`ArchiveError`。

崩溃恢复
========
提交点是 manifest 的原子替换：先落分段文件，再原子更新 manifest。
崩溃在二者之间会留下未登记的分段（孤儿）；重启时孤儿分段一律删除
——对应流水仍在当前 journal 里（只有 manifest 提交后才会裁剪），
不丢数据、不留半成品。
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .errors import ArchiveError
from .models import JournalEntry
from .persistence import entry_to_dict

log = logging.getLogger("detector.archive")

_MANIFEST = "manifest.json"
_SEG_PREFIX = "seg-"


@dataclass(frozen=True)
class ArchiveChunk:
    """一个已提交归档分段：``(prev_watermark, watermark_seq]`` 的流水。"""

    watermark_seq: int
    entries: list[JournalEntry] = field(default_factory=list)


def _manifest_path(archive_dir: Path) -> Path:
    return Path(archive_dir) / _MANIFEST


def read_manifest(archive_dir: Path) -> dict:
    """读取 manifest；缺失视为空归档，损坏显式抛 ArchiveError。"""
    path = _manifest_path(archive_dir)
    if not path.exists():
        return {"segments": [], "committed_watermark": 0}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ArchiveError(f"cannot read archive manifest {path}: {exc}") from exc
    if not isinstance(data, dict) or "segments" not in data:
        raise ArchiveError(f"invalid archive manifest {path}")
    data.setdefault("committed_watermark", 0)
    return data


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, default=str, indent=1)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


class ArchiveWriter:
    """后台归档器：接收目标水位，向引擎取区间行，原子写分段并提交 manifest。

    ``fetch_entries(prev_watermark, target_watermark)`` 由引擎提供，返回
    ``(prev, target]`` 区间的流水条目；队列里只排目标水位，连续淘汰可
    合并，写出的分段互不交叠。
    """

    def __init__(
        self,
        archive_dir: Path,
        *,
        fetch_entries: Callable[[int, int], list[JournalEntry]],
        on_commit: Callable[[ArchiveChunk], None] | None = None,
    ) -> None:
        self.archive_dir = Path(archive_dir)
        self._fetch_entries = fetch_entries
        self._on_commit = on_commit
        self._wake = threading.Event()
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._failed: Exception | None = None
        self._last_watermark = 0
        # 单飞：已请求的最高目标水位；工作线程每次把 (last, target] 提交。
        # _pending 只在 “有尚未提交的目标” 时为 1，提交中到来的更高目标
        # 原地抬升（同一连续前缀，不重复占体积），不新增分段计数。
        self._pending = 0
        self._target = 0
        self._stopping = False
        self._manifest: dict = {"segments": [], "committed_watermark": 0}

    # ---- 生命周期 ----
    def start(self) -> None:
        with self._lock:
            if self._thread is not None:
                return
            try:
                self.archive_dir.mkdir(parents=True, exist_ok=True)
                self._manifest = read_manifest(self.archive_dir)
                self._reconcile_orphans()
                self._last_watermark = int(
                    self._manifest.get("committed_watermark", 0))
            except Exception as exc:
                self._failed = exc
                raise
            thread = threading.Thread(
                target=self._run, name="archive-writer", daemon=True)
            self._thread = thread
            thread.start()
            log.info("archive writer started dir=%s watermark=%s",
                     self.archive_dir, self._last_watermark)

    def stop(self, timeout: float = 10.0) -> None:
        """等待已排队目标落盘后退出（主要用于测试/优雅关闭）。"""
        thread = self._thread
        if thread is None:
            return
        with self._lock:
            self._stopping = True
        self._wake.set()
        thread.join(timeout=timeout)

    def _reconcile_orphans(self) -> None:
        listed = {s["segment"] for s in self._manifest.get("segments", [])}
        for file in self.archive_dir.glob(f"{_SEG_PREFIX}*.jsonl"):
            if file.name not in listed:
                # 未提交的孤儿分段：对应数据仍在 journal 中，安全删除
                file.unlink(missing_ok=True)
                log.warning("removed uncommitted orphan segment %s", file)

    # ---- 摄入侧（引擎锁外调用） ----
    def submit(self, target_watermark: int, max_pending: int) -> None:
        """登记一个淘汰目标水位；失败/未启动/积压超限时显式拒绝。

        单飞语义：已有在途目标时，只把目标抬升到更高水位（内存里仍是同
        一份连续前缀），不新增在途分段；``max_pending`` 语义为“已经在途
        提交之后，又积累了多少个未跟入的水位批次”，用于在归档持续故障
        时为其设界，避免无限积压。
        """
        with self._lock:
            if self._failed is not None:
                raise ArchiveError(
                    f"archive writer failed: {self._failed}") from self._failed
            if self._thread is None:
                raise ArchiveError("archive writer not started")
            if target_watermark <= self._last_watermark:
                return  # 已提交过的水位，幂等忽略
            if target_watermark <= self._target:
                return  # 已请求更高目标，覆盖即可
            # 已有一个在途分段，且其后又堆积了 >= max_pending 个未跟入批次
            queued_behind = max(0, self._pending - 1)
            if queued_behind >= max_pending:
                from .errors import ArchiveBackpressureError

                raise ArchiveBackpressureError(
                    f"archive queued targets behind in-flight "
                    f"{queued_behind} >= {max_pending}; ingestion rejected "
                    f"to bound memory")
            self._target = target_watermark
            self._pending += 1
        self._wake.set()

    def wait_idle(self, timeout: float = 10.0) -> bool:
        """等待所有已排队目标处理完成（测试用）。"""
        deadline = threading.Event()

        def _waiter():
            while True:
                with self._lock:
                    if self._pending == 0 or self._failed is not None:
                        deadline.set()
                        return
                self._wake.wait(timeout=0.05)

        threading.Thread(target=_waiter, daemon=True).start()
        return deadline.wait(timeout)

    @property
    def pending(self) -> int:
        with self._lock:
            return self._pending

    @property
    def failed(self) -> Exception | None:
        with self._lock:
            return self._failed

    def committed_watermark(self) -> int:
        with self._lock:
            return self._last_watermark

    # ---- 后台线程（严格单飞：同一时刻最多一个分段在提交） ----
    def _run(self) -> None:
        while True:
            self._wake.wait(timeout=1.0)
            self._wake.clear()
            with self._lock:
                target = self._target
                stopping = self._stopping
                inflight = self._pending > 0
            # 没有新目标（目标已提交或从未设置）
            if target <= self._last_watermark or not inflight:
                if stopping:
                    return
                continue
            try:
                # 向引擎取 (last, target] 区间行：分段严格不交叠。
                # target 是此刻最高请求水位；本次提交后 last 直达 target。
                entries = self._fetch_entries(self._last_watermark, target)
                self._commit_chunk(target, entries)
            except BaseException as exc:  # 归档失败：显式记录，拒绝后续摄入
                with self._lock:
                    self._failed = exc
                log.error("archive commit failed at target=%s: %s",
                          target, exc)
            finally:
                with self._lock:
                    self._pending = 0
                    # 若提交期间又有更高目标到来，保留其等待标志
                    if self._target > self._last_watermark and self._failed is None:
                        self._pending = 1
            if self._pending == 0 and stopping:
                return
            if self._pending:
                self._wake.set()

    def _commit_chunk(self, target: int, entries: list[JournalEntry]) -> None:
        """落分段 -> 更新 manifest（提交点）。任何半成品都由原子写兜底。"""
        segments = self._manifest.get("segments", [])
        seg_name = f"{_SEG_PREFIX}{len(segments) + 1:08d}.jsonl"
        seg_path = self.archive_dir / seg_name
        if any(e.seq <= self._last_watermark or e.seq > target
               for e in entries):
            raise ArchiveError(
                f"archive rows outside boundary ({self._last_watermark}, "
                f"{target}]")
        self._write_segment(seg_path, entries)
        new_manifest = {
            "segments": segments + [
                {"segment": seg_name, "watermark_seq": target}],
            "committed_watermark": target,
        }
        _atomic_write_json(_manifest_path(self.archive_dir), new_manifest)
        self._manifest = new_manifest
        with self._lock:
            self._last_watermark = target
        log.info("archived segment+manifest committed seg=%s watermark=%s rows=%s",
                 seg_name, target, len(entries))
        # manifest 原子替换之后才回调：引擎侧裁剪 journal、推进快照
        if self._on_commit is not None:
            self._on_commit(ArchiveChunk(target, list(entries)))

    def _write_segment(self, path: Path, entries: list[JournalEntry]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
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

    # ---- 重放侧（显式调用） ----
    def read_archived_rows(self) -> list[dict]:
        """按 manifest 顺序读出全部归档流水行；缺失/损坏显式报错。"""
        manifest = read_manifest(self.archive_dir)
        rows: list[dict] = []
        prev_watermark = 0
        for seg in manifest.get("segments", []):
            name = seg.get("segment")
            watermark = int(seg.get("watermark_seq", 0))
            if not name or watermark <= prev_watermark:
                raise ArchiveError(
                    f"invalid manifest segment entry: {seg}")
            path = self.archive_dir / name
            if not path.exists():
                raise ArchiveError(f"archived segment missing: {path}")
            seg_rows = self._read_segment(path)
            for row in seg_rows:
                if row.get("seq", 0) > watermark or row.get("seq", 0) <= prev_watermark:
                    raise ArchiveError(
                        f"segment {name} seq {row.get('seq')} outside "
                        f"boundary ({prev_watermark}, {watermark}]")
            rows.extend(seg_rows)
            prev_watermark = watermark
        committed = int(manifest.get("committed_watermark", 0))
        if manifest.get("segments") and prev_watermark != committed:
            raise ArchiveError(
                f"manifest committed_watermark {committed} != last "
                f"segment {prev_watermark}")
        return rows

    @staticmethod
    def _read_segment(path: Path) -> list[dict]:
        rows: list[dict] = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ArchiveError(
                            f"corrupt archive segment {path}:{line_no}: {exc}"
                        ) from exc
                    if not isinstance(row, dict) or "seq" not in row:
                        raise ArchiveError(
                            f"invalid archive row {path}:{line_no}")
                    rows.append(row)
        except OSError as exc:
            raise ArchiveError(f"cannot read archive segment {path}: {exc}") from exc
        return rows
