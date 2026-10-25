"""Background jobs for the web interface (hashing evidence, running analyses, reports).

Jobs report structured progress (current checkpoint, done/total when known) and the long
multi-step kinds (triage, playbook) can be cancelled cooperatively: the cancellation lands
at the job's own checkpoints, so no module or step is interrupted half-way.
"""

from __future__ import annotations

import threading
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from forense.core.case import Case
from forense.core.errors import ForenseError
from forense.core.utils import utc_now

# Kinds whose work is divided in checkpoints the web layer drives (triage modules,
# playbook steps): cancelling one stops the remaining checkpoints, never half a module.
COOPERATIVE = frozenset({"triage", "auto"})


class JobCancelled(BaseException):
    """Cooperative cancellation raised at a checkpoint.

    ``BaseException`` on purpose: the per-step and per-module handlers in the core catch
    ``Exception`` and would swallow a cancellation as one more failed step.
    """


@dataclass
class Job:
    id: str
    case: str
    kind: str
    description: str
    status: str = "queued"  # queued | running | done | failed | cancelled
    progress: str = ""
    stage: str = ""  # current checkpoint: module, playbook step, hashing summary
    done: int = 0
    total: int = 0  # 0 = unknown
    cancel_requested: bool = False
    message: str = ""
    link: Optional[tuple[str, dict]] = None  # (endpoint, params), turned into a URL by the web layer
    created: str = field(default_factory=utc_now)
    finished: Optional[str] = None

    def as_dict(self) -> dict:
        data = dict(self.__dict__)
        data.pop("link")
        return data

    def cancellable(self) -> bool:
        """Queued jobs always; running ones only between their own checkpoints."""
        if self.status == "queued":
            return True
        return self.status == "running" and self.kind in COOPERATIVE


class Progress:
    """Callable the job functions use to report progress, with the job's metrics attached.

    Plain calls carry a text snapshot (what the core already sends). ``checkpoint`` counts a
    completed unit of work, ``metrics`` sets structured values (done/total/stage) for callers
    that know more than a string, and every entry point honours a requested cancellation.
    """

    def __init__(self, job: Job, cancellable: bool) -> None:
        self.job = job
        self._cancellable = cancellable

    def _gate(self) -> None:
        if self._cancellable and self.job.cancel_requested:
            raise JobCancelled()

    def __call__(self, *args: object) -> None:
        self._gate()
        text = " · ".join(str(a) for a in args if str(a))[:200]
        if text:
            self.job.progress = text
            self.job.stage = text[:120]

    def checkpoint(self, label: str, title: Optional[str] = None) -> None:
        """One unit of work finished (e.g. a triage module is about to run)."""
        self._gate()
        self.job.done += 1
        self.job.stage = (title or label)[:120]

    def metrics(self, *, done: Optional[int] = None, total: Optional[int] = None,
                stage: Optional[str] = None) -> None:
        self._gate()
        if done is not None:
            self.job.done = max(self.job.done, int(done))
        if total is not None:
            self.job.total = max(self.job.total, int(total))
        if stage is not None:
            self.job.stage = str(stage)[:120]


# A job function returns (message, (endpoint, url params)) for the result link.
JobFunc = Callable[[Case, Progress], tuple[str, tuple[str, dict]]]


class JobManager:
    def __init__(self, workers: int = 2) -> None:
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="forense-job")
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, case_dir: Path, case_slug: str, kind: str, description: str, func: JobFunc,
               lang: Optional[str] = None) -> Job:
        job = Job(uuid.uuid4().hex[:12], case_slug, kind, description)
        with self._lock:
            self._jobs[job.id] = job
        self._executor.submit(self._run, job, case_dir, func, lang)
        return job

    def _run(self, job: Job, case_dir: Path, func: JobFunc, lang: Optional[str]) -> None:
        from forense.i18n import set_language

        set_language(lang)
        with self._lock:  # a queued cancel must win over the worker starting
            if job.cancel_requested:
                job.status, job.finished = "cancelled", utc_now()
                return
            job.status = "running"
        try:
            with Case.open(case_dir) as case:
                job.message, job.link = func(case, Progress(job, cancellable=job.kind in COOPERATIVE))
            job.status = "done"
        except JobCancelled:
            job.status = "cancelled"
        except ForenseError as exc:
            job.status, job.message = "failed", exc.message(lang)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user, details kept for debugging
            job.status, job.message = "failed", f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        finally:
            job.finished = utc_now()

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> Optional[str]:
        """Ask one job to cancel; returns the outcome for the caller to localize.

        ``"queued"`` settles the job right away; ``"requested"`` arms the cooperative
        checkpoint; ``"unavailable"`` means the work in flight cannot stop safely;
        ``None`` means there was nothing to cancel.
        """
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.status not in ("queued", "running"):
                return None
            if job.status == "queued":
                job.cancel_requested = True
                job.status, job.finished = "cancelled", utc_now()
                return "queued"
            if job.kind not in COOPERATIVE:
                return "unavailable"
            job.cancel_requested = True
            return "requested"

    def list(self, case_slug: Optional[str] = None) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if case_slug is not None:
            jobs = [j for j in jobs if j.case == case_slug]
        jobs = sorted(jobs, key=lambda j: j.created, reverse=True)
        jobs.sort(key=lambda j: j.status not in ("queued", "running"))  # stable: the queue first
        return jobs

    def active(self, case_slug: Optional[str] = None) -> list[Job]:
        return [j for j in self.list(case_slug) if j.status in ("queued", "running")]
