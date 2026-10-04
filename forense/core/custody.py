"""Tamper-evident chain of custody.

Every entry stores the SHA-256 of the previous entry, and its own hash covers
all of its fields. Editing, deleting or reordering any entry breaks the chain
from that point on, which :meth:`ChainOfCustody.verify` reports.

The hash of the last entry (the chain *head*) should be recorded outside the
case (in the signed report, an e-mail, a ticket...) to anchor the chain: an
attacker able to rewrite the whole database could otherwise recompute it.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Optional

from forense.core.utils import utc_now

GENESIS = "0" * 64


@dataclass(frozen=True)
class CustodyEntry:
    seq: int
    timestamp: str
    action: str
    actor: str
    details: dict
    prev_hash: str
    hash: str

    def as_dict(self) -> dict:
        return {
            "seq": self.seq, "timestamp": self.timestamp, "action": self.action, "actor": self.actor,
            "details": self.details, "prev_hash": self.prev_hash, "hash": self.hash,
        }


@dataclass(frozen=True)
class CustodyProblem:
    seq: int
    code: str  # i18n key: custody.problem.*


def entry_hash(seq: int, timestamp: str, action: str, actor: str, details: dict, prev_hash: str) -> str:
    canonical = json.dumps(
        {"seq": seq, "timestamp": timestamp, "action": action, "actor": actor,
         "details": details, "prev_hash": prev_hash},
        sort_keys=True, ensure_ascii=False, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ChainOfCustody:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def append(self, action: str, actor: str, details: Optional[dict] = None) -> CustodyEntry:
        """Append an entry atomically (safe with concurrent CLI and web processes)."""
        details = details or {}
        own_tx = not self.conn.in_transaction
        if own_tx:
            self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT seq, hash FROM custody ORDER BY seq DESC LIMIT 1").fetchone()
            seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
            timestamp = utc_now()
            digest = entry_hash(seq, timestamp, action, actor, details, prev)
            self.conn.execute(
                "INSERT INTO custody (seq, timestamp, action, actor, details, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (seq, timestamp, action, actor, json.dumps(details, ensure_ascii=False, sort_keys=True), prev, digest),
            )
            if own_tx:
                self.conn.execute("COMMIT")
        except BaseException:
            if own_tx:
                self.conn.execute("ROLLBACK")
            raise
        return CustodyEntry(seq, timestamp, action, actor, details, prev, digest)

    def entries(self) -> list[CustodyEntry]:
        rows = self.conn.execute(
            "SELECT seq, timestamp, action, actor, details, prev_hash, hash FROM custody ORDER BY seq"
        ).fetchall()
        return [CustodyEntry(r[0], r[1], r[2], r[3], json.loads(r[4]), r[5], r[6]) for r in rows]

    def head(self) -> Optional[str]:
        row = self.conn.execute("SELECT hash FROM custody ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def verify(self) -> list[CustodyProblem]:
        problems: list[CustodyProblem] = []
        prev = GENESIS
        expected_seq = 1
        rows = self.conn.execute(
            "SELECT seq, timestamp, action, actor, details, prev_hash, hash FROM custody ORDER BY seq"
        ).fetchall()
        for seq, timestamp, action, actor, details_raw, prev_hash, digest in rows:
            if seq != expected_seq:
                problems.append(CustodyProblem(seq, "custody.problem.sequence_gap"))
            try:
                details = json.loads(details_raw)
            except json.JSONDecodeError:
                problems.append(CustodyProblem(seq, "custody.problem.malformed"))
                prev, expected_seq = digest, seq + 1
                continue
            if prev_hash != prev:
                problems.append(CustodyProblem(seq, "custody.problem.broken_link"))
            if entry_hash(seq, timestamp, action, actor, details, prev_hash) != digest:
                problems.append(CustodyProblem(seq, "custody.problem.altered"))
            prev, expected_seq = digest, seq + 1
        return problems
