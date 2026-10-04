"""Background jobs for the web interface (hashing evidence, running analyses, reports)."""

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


@dataclass
class Job:
    id: str
    case: str
    kind: str
    description: str
    status: str = "queued"  # queued | running | done | failed
    progress: str = ""
    message: str = ""
    link: Optional[tuple[str, dict]] = None  # (endpoint, params), turned into a URL by the web layer
    created: str = field(default_factory=utc_now)
    finished: Optional[str] = None

    def as_dict(self) -> dict:
        data = dict(self.__dict__)
        data.pop("link")
        return data


# A job function returns (message, (endpoint, url params)) for the result link.
JobFunc = Callable[[Case, Callable[[str], None]], tuple[str, tuple[str, dict]]]


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
        job.status = "running"

        def progress(text: str) -> None:
            job.progress = str(text)[:200]

        try:
            with Case.open(case_dir) as case:
                job.message, job.link = func(case, progress)
            job.status = "done"
        except ForenseError as exc:
            job.status, job.message = "failed", exc.message(lang)
        except Exception as exc:  # noqa: BLE001 - surfaced to the user, details kept for debugging
            job.status, job.message = "failed", f"{type(exc).__name__}: {exc}"
            traceback.print_exc()
        finally:
            job.finished = utc_now()

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list(self, case_slug: Optional[str] = None) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if case_slug is not None:
            jobs = [j for j in jobs if j.case == case_slug]
        return sorted(jobs, key=lambda j: j.created, reverse=True)

    def active(self, case_slug: Optional[str] = None) -> list[Job]:
        return [j for j in self.list(case_slug) if j.status in ("queued", "running")]
