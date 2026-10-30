"""NTFS $LogFile: metadata operations of the file system journal.

For every operation that carries a file name in its own data it reports the LSN,
the transaction, the operation and the name: MFT record initializations (files
created or reinitialized) and directory index entries added or deleted (files
that entered or left a directory). Attribute-level operations (create/delete
attribute, value and mapping pairs updates) name no file themselves: their
context is the open attribute table, which is rebuilt while the log is walked
so those operations are reported too, with the file (when its name appeared
earlier in the log) and the attribute they touch in the ``attribute`` field.
The log holds no timestamps, so this artifact is a table of operations, not
timeline events.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Optional

from sabueso.core.utils import find_files, relative_name
from sabueso.modules.base import AnalysisContext, Module, register
from sabueso.parsers.logfile import (
    CONTEXT_OPS,
    NAME_OPS,
    OP_INDEX_ALLOC_ADD,
    OP_INDEX_ALLOC_DELETE,
    OP_INDEX_ROOT_ADD,
    OP_INDEX_ROOT_DELETE,
    OP_INITIALIZE_FILE_RECORD,
    OP_NAME_ALLOC_UPDATE,
    OP_NAME_ROOT_UPDATE,
    LogFileError,
    LogRecord,
    OpenAttributes,
    attribute_display,
    file_name_from_content,
    file_record_from_data,
    index_entry_file_name,
    iter_records,
    open_logfile,
    operation_name,
)

_ADD_OPS = frozenset({OP_INDEX_ROOT_ADD, OP_INDEX_ALLOC_ADD})
_DELETE_OPS = frozenset({OP_INDEX_ROOT_DELETE, OP_INDEX_ALLOC_DELETE})
_NAME_UPDATE_OPS = frozenset({OP_NAME_ROOT_UPDATE, OP_NAME_ALLOC_UPDATE})


@register
class LogFileModule(Module):
    name = "logfile"
    category = "windows"
    triage = True

    def discover(self, target: Path) -> list[Path]:
        return find_files(target, lambda p: p.name.lower() in ("$logfile", "logfile", "$logfile.bin"))

    def analyze(self, ctx: AnalysisContext) -> None:
        ctx.summary["logfile_files"] = {}
        for path in self.discover(ctx.target):
            rel = relative_name(path, ctx.target)
            try:
                self._analyze_file(ctx, path, rel)
            except (OSError, LogFileError) as exc:
                ctx.error(rel, exc)

    def _analyze_file(self, ctx: AnalysisContext, path: Path, rel: str) -> None:
        stats: Counter = Counter()
        ctx.progress(f"{rel}: records")
        fh, info = open_logfile(path)
        try:
            table = OpenAttributes()
            names: dict[int, str] = {}
            for record in iter_records(fh, info):
                stats["records"] += 1
                table.update(record)
                named = self._named(record)
                if named is not None:
                    stats["named"] += 1
                    op, file_ref, parent_ref, name = named
                    if file_ref is not None:
                        names.setdefault(file_ref, name)
                    ctx.record("logfile_entry", {
                        "lsn": record.lsn, "transaction": record.transaction_id, "operation": op,
                        "record": file_ref if file_ref is not None else "",
                        "parent_record": parent_ref if parent_ref is not None else "", "name": name,
                        "attribute": self._attribute(record, table),
                    })
                    continue
                contextual = self._contextual(record, table, names)
                if contextual is not None:
                    stats["contextual"] += 1
                    op, number, name, attribute = contextual
                    ctx.record("logfile_entry", {
                        "lsn": record.lsn, "transaction": record.transaction_id, "operation": op,
                        "record": number, "parent_record": "", "name": name, "attribute": attribute,
                    })
        finally:
            fh.close()
        ctx.summary["logfile_files"][rel] = dict(stats)

    @staticmethod
    def _attribute(record: LogRecord, table: OpenAttributes) -> str:
        entry = table.lookup(record.target_attribute)
        return attribute_display(entry) if entry is not None else ""

    def _contextual(self, record: LogRecord, table: OpenAttributes,
                    names: dict[int, str]) -> Optional[tuple[str, int, str, str]]:
        """(operation, record number, file name, attribute) when the operation's context is
        the open attribute table: which file and which attribute the change applies to."""
        op = record.redo_op if record.redo_op in CONTEXT_OPS else record.undo_op
        if op not in CONTEXT_OPS:
            return None
        entry = table.lookup(record.target_attribute)
        if entry is None:
            return None
        number = entry.reference & 0xFFFFFFFFFFFF
        display = self._attribute(record, table)
        return operation_name(op), number, names.get(number, ""), display

    def _named(self, record: LogRecord) -> Optional[tuple[str, Optional[int], Optional[int], str]]:
        """(operation, file reference, parent reference, name) when the operation carries a name.

        Add operations carry the entry in the redo data, delete operations in the undo
        data; when both operations are name-bearing the redo data is preferred.
        """
        op = record.redo_op if record.redo_op in NAME_OPS else record.undo_op
        if op not in NAME_OPS:
            return None
        data = record.redo_data if op == record.redo_op else record.undo_data
        if op in _ADD_OPS or op in _DELETE_OPS:
            decoded = index_entry_file_name(data)
            if decoded is None:
                return None
            file_ref, parent_ref, name = decoded
            kind = "index_entry_add" if op in _ADD_OPS else "index_entry_delete"
            return kind, file_ref, parent_ref, name
        if op in _NAME_UPDATE_OPS:
            decoded = file_name_from_content(data)
            if decoded is None:
                return None
            parent_ref, name = decoded
            return "file_name_update", None, parent_ref, name
        if op == OP_INITIALIZE_FILE_RECORD:
            entry = file_record_from_data(data)
            if entry is not None and entry.name:
                return operation_name(op), entry.record, entry.parent_record, entry.name
        return None
