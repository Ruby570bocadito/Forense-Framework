"""Investigation case: evidence, analyses, timeline, findings and chain of custody.

A case is a directory::

    <case>/
      forense.db      SQLite database (WAL): case data, results and custody chain
      evidence/       verified working copies of evidence (``--copy``)
      analyses/       files produced by analyses (carved files, bodyfiles...)
      reports/        generated reports
      exports/        exported CSV/JSON

Evidence is never written to: it is hashed when registered, opened read-only
by every module and can be re-verified at any time.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import sys
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional

from forense import __version__
from forense.core.custody import ChainOfCustody
from forense.core.errors import CaseError, ForenseError
from forense.core.hashing import DEFAULT_ALGORITHMS, ProgressCallback, hash_file, hash_tree
from forense.core.review import REVIEW_SCHEMA, ReviewMixin, latest_review_sql
from forense.core.utils import utc_now
from forense.i18n import t

DB_NAME = "forense.db"
SCHEMA_VERSION = 1
SUBDIRS = ("evidence", "analyses", "reports", "exports")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY, path TEXT NOT NULL, source TEXT NOT NULL, kind TEXT NOT NULL,
    size INTEGER NOT NULL, file_count INTEGER NOT NULL, hashes TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '', added_at TEXT NOT NULL, added_by TEXT NOT NULL,
    copied INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS custody (
    seq INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, action TEXT NOT NULL, actor TEXT NOT NULL,
    details TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT, module TEXT NOT NULL, evidence_id TEXT NOT NULL,
    status TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, options TEXT NOT NULL DEFAULT '{}',
    summary TEXT NOT NULL DEFAULT '{}', errors TEXT NOT NULL DEFAULT '[]', artifacts TEXT NOT NULL DEFAULT '[]',
    actor TEXT NOT NULL, output_dir TEXT NOT NULL DEFAULT '', record_count INTEGER NOT NULL DEFAULT 0,
    event_count INTEGER NOT NULL DEFAULT 0, finding_count INTEGER NOT NULL DEFAULT 0, results_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS records (
    analysis_id INTEGER NOT NULL, seq INTEGER NOT NULL, artifact TEXT NOT NULL, data TEXT NOT NULL,
    PRIMARY KEY (analysis_id, seq)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL, evidence_id TEXT NOT NULL,
    timestamp TEXT NOT NULL, source TEXT NOT NULL, type TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '', severity TEXT NOT NULL DEFAULT 'info'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_analysis ON events(analysis_id);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, analysis_id INTEGER NOT NULL, evidence_id TEXT NOT NULL,
    severity TEXT NOT NULL, code TEXT NOT NULL, timestamp TEXT, params TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_findings_analysis ON findings(analysis_id);
""" + REVIEW_SCHEMA

SEVERITY_ORDER_SQL = ("CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 "
                      "WHEN 'low' THEN 1 ELSE 0 END")


@dataclass
class Evidence:
    id: str
    path: str
    source: str
    kind: str  # "file" | "directory"
    size: int
    file_count: int
    hashes: dict
    description: str
    added_at: str
    added_by: str
    copied: bool
    derived_from: Optional[str] = None  # evidence id this was extracted from (disk images)

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Evidence":
        return cls(row["id"], row["path"], row["source"], row["kind"], row["size"], row["file_count"],
                   json.loads(row["hashes"]), row["description"], row["added_at"], row["added_by"],
                   bool(row["copied"]), row["derived_from"])


@dataclass
class Verification:
    evidence_id: str
    ok: bool
    expected: dict
    current: dict
    error: Optional[str] = None  # i18n code when the evidence could not be read


@dataclass
class Analysis:
    id: int
    module: str
    evidence_id: str
    status: str  # running | completed | failed | interrupted
    started: str
    finished: Optional[str]
    options: dict
    summary: dict
    errors: list
    artifacts: list
    actor: str
    output_dir: str
    record_count: int
    event_count: int
    finding_count: int
    results_sha256: Optional[str]

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Analysis":
        return cls(row["id"], row["module"], row["evidence_id"], row["status"], row["started"], row["finished"],
                   json.loads(row["options"]), json.loads(row["summary"]), json.loads(row["errors"]),
                   json.loads(row["artifacts"]), row["actor"], row["output_dir"], row["record_count"],
                   row["event_count"], row["finding_count"], row["results_sha256"])


@dataclass
class Page:
    total: int
    rows: list = field(default_factory=list)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[None]:
    """Explicit write transaction (connections run in autocommit mode)."""
    if conn.in_transaction:
        yield
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


class _CaseSink:
    """Streams module output into the case database."""

    def __init__(self, conn: sqlite3.Connection, analysis_id: int, evidence_id: str) -> None:
        self.conn = conn
        self.analysis_id = analysis_id
        self.evidence_id = evidence_id
        self.seq = 0

    def add_records(self, items: list[tuple[str, dict]]) -> None:
        # Stored in the module's field order (for display); hashes use the canonical, key-sorted form.
        rows = []
        for artifact, data in items:
            self.seq += 1
            rows.append((self.analysis_id, self.seq, artifact,
                         json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)))
        with transaction(self.conn):
            self.conn.executemany("INSERT INTO records (analysis_id, seq, artifact, data) VALUES (?,?,?,?)", rows)

    def add_events(self, items: list[dict]) -> None:
        with transaction(self.conn):
            self.conn.executemany(
                "INSERT INTO events (analysis_id, evidence_id, timestamp, source, type, details, path, severity) "
                "VALUES (?,?,?,?,?,?,?,?)",
                [(self.analysis_id, self.evidence_id, e["timestamp"], e["source"], e["type"], e["details"],
                  e["path"], e["severity"]) for e in items],
            )

    def add_findings(self, items: list[dict]) -> None:
        from forense.modules.base import canonical

        with transaction(self.conn):
            self.conn.executemany(
                "INSERT INTO findings (analysis_id, evidence_id, severity, code, timestamp, params) "
                "VALUES (?,?,?,?,?,?)",
                [(self.analysis_id, self.evidence_id, f["severity"], f["code"], f["timestamp"],
                  canonical(f["params"])) for f in items],
            )


class Case(ReviewMixin):
    def __init__(self, root: Path, conn: sqlite3.Connection) -> None:
        self.root = Path(root)
        self.conn = conn
        self.custody = ChainOfCustody(conn)

    # -- lifecycle --------------------------------------------------------
    @staticmethod
    def is_case(root: Path) -> bool:
        return (Path(root) / DB_NAME).is_file()

    @staticmethod
    def _connect(db_path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(str(db_path), timeout=30, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        return conn

    @classmethod
    def create(cls, root: Path, name: str, investigator: str, description: str = "",
               reference: str = "", organization: str = "") -> "Case":
        root = Path(root).resolve()
        if cls.is_case(root):
            raise CaseError("error.case_exists", path=str(root))
        if not name.strip() or not investigator.strip():
            raise CaseError("error.case_fields_required")
        root.mkdir(parents=True, exist_ok=True)
        for sub in SUBDIRS:
            (root / sub).mkdir(exist_ok=True)
        conn = cls._connect(root / DB_NAME)
        conn.executescript(_SCHEMA)
        _migrate(conn)
        now = datetime.now(timezone.utc)
        meta = {
            "id": f"CASE-{now:%Y%m%d}-{uuid.uuid4().hex[:6].upper()}",
            "name": name.strip(),
            "investigator": investigator.strip(),
            "description": description.strip(),
            "reference": reference.strip(),
            "organization": organization.strip(),
            "created": utc_now(),
            "framework_version": __version__,
            "schema_version": str(SCHEMA_VERSION),
        }
        with transaction(conn):
            conn.executemany("INSERT INTO meta (key, value) VALUES (?, ?)", meta.items())
        case = cls(root, conn)
        case.custody.append("case_created", meta["investigator"],
                            {"case_id": meta["id"], "name": meta["name"], "framework_version": __version__})
        return case

    @classmethod
    def open(cls, root: Path) -> "Case":
        root = Path(root).resolve()
        if not cls.is_case(root):
            raise CaseError("error.case_not_found", path=str(root))
        conn = cls._connect(root / DB_NAME)
        conn.executescript(_SCHEMA)
        _migrate(conn)
        return cls(root, conn)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Case":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- metadata ---------------------------------------------------------
    @property
    def info(self) -> dict:
        return {row["key"]: row["value"] for row in self.conn.execute("SELECT key, value FROM meta")}

    @property
    def name(self) -> str:
        return self.info.get("name", "")

    def actor(self, actor: Optional[str]) -> str:
        return (actor or "").strip() or self.info.get("investigator", "unknown")

    # -- evidence ---------------------------------------------------------
    def _next_evidence_id(self) -> str:
        numbers = [int(row[0][3:]) for row in self.conn.execute("SELECT id FROM evidence")
                   if row[0].startswith("EV-") and row[0][3:].isdigit()]
        return f"EV-{max(numbers, default=0) + 1:03d}"

    @staticmethod
    def _measure(path: Path, progress: Optional[ProgressCallback]) -> tuple[str, dict, int, int]:
        if path.is_file():
            done = 0

            def _file_progress(n: int) -> None:
                nonlocal done
                done += n
                if progress:
                    progress(0, done)

            hashes = hash_file(path, DEFAULT_ALGORITHMS, progress=_file_progress)
            return "file", hashes, path.stat().st_size, 1
        if path.is_dir():
            tree = hash_tree(path, DEFAULT_ALGORITHMS, progress=progress)
            return "directory", tree.hashes, tree.total_size, tree.file_count
        raise CaseError("error.evidence_unsupported", path=str(path))

    def add_evidence(self, source: Path, description: str = "", copy: bool = False,
                     actor: Optional[str] = None, progress: Optional[ProgressCallback] = None,
                     derived_from: Optional[str] = None, analysis_id: Optional[int] = None) -> Evidence:
        """Register evidence: hash it and, with ``copy``, make a verified read-only working copy.

        ``derived_from`` registers files produced by the case itself (artifacts extracted from a disk
        image by analysis ``analysis_id``); they live in the case folder and are made read-only.
        """
        source = Path(source).expanduser().resolve()
        if not source.exists():
            raise CaseError("error.evidence_missing", path=str(source))
        inside = source == self.root or self.root in source.parents
        if inside and not (derived_from and (self.root / "analyses") in source.parents):
            raise CaseError("error.evidence_inside_case", path=str(source))
        if derived_from:
            self.get_evidence(derived_from)
            copy = False
        actor = self.actor(actor)
        try:
            kind, hashes, size, count = self._measure(source, progress)
        except OSError as exc:
            raise CaseError("error.evidence_unreadable", path=str(source), error=str(exc)) from exc

        evidence_id = self._next_evidence_id()
        work_path = source
        if copy:
            work_path = self._copy_evidence(source, evidence_id, kind, hashes, progress)

        evidence = Evidence(evidence_id, str(work_path), str(source), kind, size, count, hashes,
                            description.strip(), utc_now(), actor, copy, derived_from)
        if derived_from:
            _make_read_only(source)
        with transaction(self.conn):
            self.conn.execute(
                "INSERT INTO evidence (id, path, source, kind, size, file_count, hashes, description, added_at, "
                "added_by, copied, derived_from) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (evidence.id, evidence.path, evidence.source, kind, size, count, json.dumps(hashes),
                 evidence.description, evidence.added_at, actor, int(copy), derived_from),
            )
            details = {"evidence_id": evidence_id, "source": str(source), "path": str(work_path), "kind": kind,
                       "size": size, "file_count": count, "copied": copy, **hashes}
            if derived_from:
                details.update({"derived_from": derived_from, "analysis_id": analysis_id})
            self.custody.append("evidence_derived" if derived_from else "evidence_added", actor, details)
        return evidence

    def extract_image(self, evidence_id: str, options: Optional[dict] = None, actor: Optional[str] = None,
                      progress: Optional[Callable[[str], None]] = None) -> tuple["Analysis", Optional[Evidence]]:
        """Extract artifacts from a disk image and register them as derived evidence."""
        analysis = self.run_analysis("image", evidence_id, options, actor, progress)
        extracted = self.root / analysis.output_dir / "extracted"
        if not analysis.summary.get("files_extracted") or not extracted.is_dir():
            return analysis, None
        source = self.get_evidence(evidence_id)
        description = t("evidence.derived_description", source=source.description or source.id, analysis=analysis.id)
        derived = self.add_evidence(extracted, description, actor=actor, derived_from=source.id,
                                    analysis_id=analysis.id)
        return analysis, derived

    def _copy_evidence(self, source: Path, evidence_id: str, kind: str, expected: dict,
                       progress: Optional[ProgressCallback]) -> Path:
        dest_dir = self.root / "evidence" / evidence_id
        dest = dest_dir / source.name
        dest_dir.mkdir(parents=True, exist_ok=False)
        try:
            if kind == "file":
                shutil.copy2(source, dest)
            else:
                shutil.copytree(source, dest, symlinks=True)
            _, copied_hashes, _, _ = self._measure(dest, progress)
            if copied_hashes != expected:
                raise CaseError("error.copy_mismatch", path=str(dest))
        except BaseException:
            _force_rmtree(dest_dir)
            raise
        _make_read_only(dest)
        return dest

    def evidence_list(self) -> list[Evidence]:
        return [Evidence.from_row(r) for r in self.conn.execute("SELECT * FROM evidence ORDER BY id")]

    def get_evidence(self, evidence_id: str) -> Evidence:
        row = self.conn.execute("SELECT * FROM evidence WHERE id = ?", (evidence_id.upper(),)).fetchone()
        if row is None:
            raise CaseError("error.evidence_unknown", evidence=evidence_id)
        return Evidence.from_row(row)

    def verify_evidence(self, evidence_id: str, actor: Optional[str] = None,
                        progress: Optional[ProgressCallback] = None) -> Verification:
        evidence = self.get_evidence(evidence_id)
        path = Path(evidence.path)
        current: dict = {}
        error = None
        if not path.exists():
            error = "verify.missing"
        else:
            try:
                _, current, _, _ = self._measure(path, progress)
            except (OSError, ForenseError):
                error = "verify.unreadable"
        ok = error is None and current == evidence.hashes
        self.custody.append("evidence_verified", self.actor(actor), {
            "evidence_id": evidence.id, "result": "ok" if ok else "mismatch" if error is None else "error",
            "sha256": current.get("sha256"),
        })
        return Verification(evidence.id, ok, evidence.hashes, current, error)

    def last_verifications(self) -> dict[str, dict]:
        """Latest verification result of each evidence item, from the chain of custody."""
        last: dict[str, dict] = {}
        for entry in self.custody.entries():
            if entry.action == "evidence_verified":
                last[entry.details.get("evidence_id")] = {"result": entry.details.get("result"),
                                                          "timestamp": entry.timestamp, "actor": entry.actor}
        return last

    # -- analyses ---------------------------------------------------------
    def run_analysis(self, module_name: str, evidence_id: str, options: Optional[dict] = None,
                     actor: Optional[str] = None, progress: Optional[Callable[[str], None]] = None) -> Analysis:
        from forense.modules.base import get_module, mask_secret

        module = get_module(module_name)
        evidence = self.get_evidence(evidence_id)
        target = Path(evidence.path)
        module.check_target(target)
        parsed = module.parse_options(options)
        actor = self.actor(actor)
        secrets = {o.name for o in module.options if o.kind == "secret"}
        stored_options = {k: mask_secret(v) if k in secrets else (str(v) if v is not None else None)
                          for k, v in parsed.items()}

        cur = self.conn.execute(
            "INSERT INTO analyses (module, evidence_id, status, started, options, actor) VALUES (?,?,?,?,?,?)",
            (module.name, evidence.id, "running", utc_now(), json.dumps(stored_options, ensure_ascii=False), actor),
        )
        analysis_id = cur.lastrowid
        output_dir = self.root / "analyses" / f"{analysis_id:04d}_{module.name}"
        self.conn.execute("UPDATE analyses SET output_dir = ? WHERE id = ?",
                          (output_dir.relative_to(self.root).as_posix(), analysis_id))
        sink = _CaseSink(self.conn, analysis_id, evidence.id)
        try:
            ctx = module.run(target, output_dir, options, sink=sink, evidence_id=evidence.id, progress=progress)
        except BaseException as exc:
            error = exc.message("en") if isinstance(exc, ForenseError) else f"{type(exc).__name__}: {exc}"
            self.conn.execute(
                "UPDATE analyses SET status = 'failed', finished = ?, errors = ? WHERE id = ?",
                (utc_now(), json.dumps([{"path": str(target), "error": error}], ensure_ascii=False), analysis_id),
            )
            self.custody.append("analysis_failed", actor, {
                "analysis_id": analysis_id, "module": module.name, "evidence_id": evidence.id, "error": error,
            })
            raise
        self.conn.execute(
            "UPDATE analyses SET status = 'completed', finished = ?, summary = ?, errors = ?, artifacts = ?, "
            "record_count = ?, event_count = ?, finding_count = ?, results_sha256 = ? WHERE id = ?",
            (utc_now(), json.dumps(ctx.summary, ensure_ascii=False, default=str),
             json.dumps(ctx.errors, ensure_ascii=False), json.dumps(ctx.artifacts, ensure_ascii=False),
             ctx.counts["records"], ctx.counts["events"], ctx.counts["findings"], ctx.results_sha256, analysis_id),
        )
        self.custody.append("analysis_completed", actor, {
            "analysis_id": analysis_id, "module": module.name, "evidence_id": evidence.id,
            "options": stored_options, "records": ctx.counts["records"], "events": ctx.counts["events"],
            "findings": ctx.counts["findings"], "errors": len(ctx.errors), "results_sha256": ctx.results_sha256,
        })
        return self.get_analysis(analysis_id)

    def triage(self, evidence_id: str, actor: Optional[str] = None,
               progress: Optional[Callable[[str], None]] = None) -> list[tuple[str, Optional[Analysis], str]]:
        """Run every triage module that finds artifacts in the evidence.

        Returns ``(module, analysis or None, error code)`` per module; a failing
        module does not stop the others.
        """
        from forense.image import is_disk_image
        from forense.modules.base import available_modules

        evidence = self.get_evidence(evidence_id)
        target = Path(evidence.path)
        results: list[tuple[str, Optional[Analysis], str]] = []
        if is_disk_image(target) or (target.is_dir() and any(is_disk_image(p) for p in target.iterdir())):
            if progress:
                progress("image")
            try:
                analysis, derived = self.extract_image(evidence.id, actor=actor, progress=progress)
            except Exception:  # noqa: BLE001 - recorded as a failed analysis
                return [("image", None, "triage.failed")]
            results.append(("image", analysis, ""))
            if derived is None:
                return results
            evidence, target = derived, Path(derived.path)
        for module in available_modules():
            if not module.triage:
                continue
            try:
                module.check_target(target)
                if not module.discover(target):
                    results.append((module.name, None, "triage.no_artifacts"))
                    continue
            except (ForenseError, OSError):
                results.append((module.name, None, "triage.not_applicable"))
                continue
            if progress:
                progress(module.name)
            try:
                results.append((module.name, self.run_analysis(module.name, evidence.id, actor=actor,
                                                               progress=progress), ""))
            except Exception:  # noqa: BLE001 - recorded as a failed analysis in the case
                results.append((module.name, None, "triage.failed"))
        return results

    def analyses(self) -> list[Analysis]:
        return [Analysis.from_row(r) for r in self.conn.execute("SELECT * FROM analyses ORDER BY id")]

    def get_analysis(self, analysis_id: int) -> Analysis:
        row = self.conn.execute("SELECT * FROM analyses WHERE id = ?", (int(analysis_id),)).fetchone()
        if row is None:
            raise CaseError("error.analysis_unknown", analysis=analysis_id)
        return Analysis.from_row(row)

    def mark_interrupted(self) -> int:
        """Flag analyses left 'running' by a crashed process."""
        cur = self.conn.execute("UPDATE analyses SET status = 'interrupted' WHERE status = 'running'")
        return cur.rowcount

    def delete_analysis(self, analysis_id: int, actor: Optional[str] = None) -> None:
        analysis = self.get_analysis(analysis_id)
        with transaction(self.conn):
            for table in ("records", "events", "findings"):
                self.conn.execute(f"DELETE FROM {table} WHERE analysis_id = ?", (analysis.id,))
            self.conn.execute("DELETE FROM analyses WHERE id = ?", (analysis.id,))
            self.custody.append("analysis_deleted", self.actor(actor), {
                "analysis_id": analysis.id, "module": analysis.module, "evidence_id": analysis.evidence_id,
                "results_sha256": analysis.results_sha256,
            })
        if analysis.output_dir:
            _force_rmtree(self.root / analysis.output_dir)

    def verify_results(self, analysis_id: int) -> bool:
        """Recompute the results hash of an analysis from the database."""
        from forense.modules.base import canonical, combine_result_hashes, item_line, record_line

        analysis = self.get_analysis(analysis_id)
        records, events, findings = hashlib.sha256(), hashlib.sha256(), hashlib.sha256()
        for row in self.conn.execute(
                "SELECT artifact, data FROM records WHERE analysis_id = ? ORDER BY seq", (analysis.id,)):
            records.update(record_line(row["artifact"], canonical(json.loads(row["data"]))))
        for row in self.conn.execute(
                "SELECT timestamp, source, type, details, path, severity FROM events WHERE analysis_id = ? "
                "ORDER BY id", (analysis.id,)):
            events.update(item_line(dict(row)))
        for row in self.conn.execute(
                "SELECT code, severity, timestamp, params FROM findings WHERE analysis_id = ? ORDER BY id",
                (analysis.id,)):
            findings.update(item_line({"code": row["code"], "severity": row["severity"],
                                       "timestamp": row["timestamp"], "params": json.loads(row["params"])}))
        digest = combine_result_hashes(records.hexdigest(), events.hexdigest(), findings.hexdigest())
        return digest == analysis.results_sha256

    # -- querying -----------------------------------------------------------
    def records(self, analysis_id: int, artifact: Optional[str] = None, search: str = "",
                offset: int = 0, limit: Optional[int] = 100) -> Page:
        where, params = ["analysis_id = ?"], [int(analysis_id)]
        if artifact:
            where.append("artifact = ?")
            params.append(artifact)
        if search:
            where.append("data LIKE ?")
            params.append(f"%{search}%")
        clause = " AND ".join(where)
        total = self.conn.execute(f"SELECT COUNT(*) FROM records WHERE {clause}", params).fetchone()[0]
        sql = f"SELECT seq, artifact, data FROM records WHERE {clause} ORDER BY seq"
        rows = self.conn.execute(sql + _limit(limit, offset), params).fetchall()
        return Page(total, [(r["artifact"], json.loads(r["data"])) for r in rows])

    def record_artifacts(self, analysis_id: int) -> list[tuple[str, int]]:
        return [(r[0], r[1]) for r in self.conn.execute(
            "SELECT artifact, COUNT(*) FROM records WHERE analysis_id = ? GROUP BY artifact ORDER BY artifact",
            (int(analysis_id),))]

    def events(self, start: Optional[str] = None, end: Optional[str] = None, search: str = "",
               source: Optional[str] = None, evidence_id: Optional[str] = None, min_severity: Optional[str] = None,
               bookmarked: bool = False, offset: int = 0, limit: Optional[int] = 200) -> Page:
        """Timeline events; each row carries ``bookmark`` (the analyst's latest mark) or None."""
        where, params = ["1=1"], []
        if start:
            where.append("e.timestamp >= ?")
            params.append(start)
        if end:
            where.append("e.timestamp <= ?")
            params.append(end)
        if search:
            where.append("(e.details LIKE ? OR e.path LIKE ? OR e.type LIKE ? OR rv.note LIKE ?)")
            params += [f"%{search}%"] * 4
        if source:
            where.append("e.source = ?")
            params.append(source)
        if evidence_id:
            where.append("e.evidence_id = ?")
            params.append(evidence_id)
        if min_severity:
            from forense.modules.base import SEVERITY_RANK

            where.append(f"{SEVERITY_ORDER_SQL.replace('severity', 'e.severity')} >= ?")
            params.append(SEVERITY_RANK.get(min_severity, 0))
        if bookmarked:
            where.append("rv.status = 'bookmarked'")
        clause = " AND ".join(where)
        source_sql = f"events e LEFT JOIN {latest_review_sql('event')} rv ON rv.target_id = e.id"
        total = self.conn.execute(f"SELECT COUNT(*) FROM {source_sql} WHERE {clause}", params).fetchone()[0]
        rows = self.conn.execute(
            f"SELECT e.*, rv.status AS review_status, rv.note AS review_note, rv.actor AS review_actor, "
            f"rv.timestamp AS review_timestamp FROM {source_sql} WHERE {clause} ORDER BY e.timestamp, e.id"
            + _limit(limit, offset), params
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            status = item.pop("review_status")
            review = {"status": status, "note": item.pop("review_note"), "actor": item.pop("review_actor"),
                      "timestamp": item.pop("review_timestamp")}
            item["bookmark"] = review if status == "bookmarked" else None
            result.append(item)
        return Page(total, result)

    def iter_events(self, **filters: object) -> Iterator[dict]:
        offset = 0
        while True:
            page = self.events(offset=offset, limit=5000, **filters)
            yield from page.rows
            if len(page.rows) < 5000:
                return
            offset += 5000

    def findings(self, min_severity: Optional[str] = None, analysis_id: Optional[int] = None,
                 evidence_id: Optional[str] = None, review_status: Optional[str] = None) -> list[dict]:
        """Findings by severity. Each one carries ``review`` with the analyst's latest verdict.

        ``review_status``: confirmed, false_positive or needs_review (not yet reviewed).
        """
        severity_sql = SEVERITY_ORDER_SQL.replace("severity", "f.severity")
        where, params = ["1=1"], []
        if min_severity:
            from forense.modules.base import SEVERITY_RANK

            where.append(f"{severity_sql} >= ?")
            params.append(SEVERITY_RANK.get(min_severity, 0))
        if analysis_id is not None:
            where.append("f.analysis_id = ?")
            params.append(int(analysis_id))
        if evidence_id:
            where.append("f.evidence_id = ?")
            params.append(evidence_id)
        if review_status:
            where.append("COALESCE(rv.status, 'needs_review') = ?")
            params.append(review_status)
        rows = self.conn.execute(
            f"SELECT f.*, COALESCE(rv.status, 'needs_review') AS review_status, rv.note AS review_note, "
            f"rv.actor AS review_actor, rv.timestamp AS review_timestamp FROM findings f "
            f"LEFT JOIN {latest_review_sql('finding')} rv ON rv.target_id = f.id WHERE {' AND '.join(where)} "
            f"ORDER BY {severity_sql} DESC, COALESCE(f.timestamp, '9999'), f.id", params
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["params"] = json.loads(item["params"])
            item["review"] = {"status": item.pop("review_status"), "note": item.pop("review_note") or "",
                              "actor": item.pop("review_actor"), "timestamp": item.pop("review_timestamp")}
            result.append(item)
        return result

    def stats(self) -> dict:
        severity = {r[0]: r[1] for r in self.conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")}
        span = self.conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events").fetchone()
        return {
            "evidence": self.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            "analyses": self.conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0],
            "events": self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "findings": sum(severity.values()),
            "findings_by_severity": severity,
            "first_event": span[0],
            "last_event": span[1],
        }

    def event_sources(self) -> list[str]:
        return [r[0] for r in self.conn.execute("SELECT DISTINCT source FROM events ORDER BY source")]


def _limit(limit: Optional[int], offset: int) -> str:
    if limit is None:
        return ""
    return f" LIMIT {int(limit)} OFFSET {max(0, int(offset))}"


def _make_read_only(path: Path) -> None:
    targets = [path] if path.is_file() else [Path(r) / f for r, _, files in os.walk(path) for f in files]
    for target in targets:
        if not target.is_symlink():
            target.chmod(stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)


def _force_rmtree(path: Path) -> None:
    def _retry(func, target, _exc):  # read-only files cannot be removed on Windows
        os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
        func(target)

    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_retry)
    else:
        shutil.rmtree(path, onerror=_retry)


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring cases created by older versions up to the current schema."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(evidence)")}
    if "derived_from" not in columns:
        conn.execute("ALTER TABLE evidence ADD COLUMN derived_from TEXT")
