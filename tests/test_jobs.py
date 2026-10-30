"""Unit tests for the web job manager: structured progress, queue order and cancellation."""

from __future__ import annotations

import threading
import time

import pytest

from sabueso.core.case import Case
from sabueso.web.jobs import Job, JobCancelled, JobManager, Progress


def _case(tmp_path):
    root = tmp_path / "c"
    with Case.create(root, "Job case", "Tester"):
        pass
    return root


def test_progress_carries_text_and_metrics():
    job = Job("abc", "c1", "triage", "desc")
    progress = Progress(job, cancellable=True)
    progress("hashing 10 files")
    assert job.progress == "hashing 10 files" and job.stage == "hashing 10 files"
    progress.checkpoint("evtx", title="Eventos de Windows")
    assert job.done == 1 and job.stage == "Eventos de Windows"
    progress.metrics(done=5, total=27)
    assert job.done == 5 and job.total == 27
    progress.metrics(done=2)  # the counters never go backwards
    assert job.done == 5 and job.total == 27


def test_progress_raises_when_cancel_requested():
    job = Job("abc", "c1", "triage", "desc")
    progress = Progress(job, cancellable=True)
    job.cancel_requested = True
    with pytest.raises(JobCancelled):
        progress("x")
    with pytest.raises(JobCancelled):
        progress.checkpoint("evtx")
    assert job.status == "queued"  # the flag alone does not change the status


def test_non_cancellable_kind_ignores_the_flag():
    job = Job("abc", "c1", "analysis", "desc")
    progress = Progress(job, cancellable=False)
    job.cancel_requested = True
    progress("module text")  # a single module cannot be stopped half-way
    assert job.progress == "module text"


def test_cancel_queued_never_runs(tmp_path):
    manager = JobManager(workers=1)
    case_root = _case(tmp_path)
    started = threading.Event()
    release = threading.Event()

    def blocker(case, progress):
        started.set()
        release.wait(5)
        return "ok", None

    def quick(case, progress):
        return "ok", None

    first = manager.submit(case_root, "c1", "analysis", "first", blocker)
    assert started.wait(5)
    second = manager.submit(case_root, "c1", "triage", "second", quick)
    assert second.status == "queued" and second.cancellable()
    assert manager.cancel(second.id) == "queued"
    assert second.status == "cancelled" and second.finished
    release.set()
    deadline = time.time() + 5
    while first.status != "done" and time.time() < deadline:
        time.sleep(0.01)
    assert first.status == "done" and second.status == "cancelled"


def test_cooperative_cancel_stops_between_checkpoints(tmp_path):
    manager = JobManager(workers=1)
    case_root = _case(tmp_path)

    def work(case, progress):
        for i in range(60):
            progress.checkpoint(f"module_{i}")
            time.sleep(0.01)
        return "never", None

    job = manager.submit(case_root, "c1", "triage", "t", work)
    deadline = time.time() + 5
    while job.status != "running" and time.time() < deadline:
        time.sleep(0.01)
    assert manager.cancel(job.id) == "requested"
    deadline = time.time() + 5
    while job.status != "cancelled" and time.time() < deadline:
        time.sleep(0.01)
    assert job.status == "cancelled" and job.done < 60  # stopped, never finished the loop


def test_cancel_unavailable_for_a_single_module(tmp_path):
    manager = JobManager(workers=1)
    running = threading.Event()
    release = threading.Event()

    def work(case, progress):
        running.set()
        release.wait(5)
        return "ok", None

    job = manager.submit(_case(tmp_path), "c1", "analysis", "a", work)
    assert running.wait(5)
    assert manager.cancel(job.id) == "unavailable"
    assert job.status == "running" and not job.cancel_requested
    release.set()
    deadline = time.time() + 5
    while job.status != "done" and time.time() < deadline:
        time.sleep(0.01)
    assert job.status == "done"


def test_cancel_of_a_finished_job_is_none(tmp_path):
    manager = JobManager(workers=1)
    job = manager.submit(_case(tmp_path), "c1", "analysis", "a",
                         lambda case, progress: ("ok", None))
    deadline = time.time() + 5
    while job.status != "done" and time.time() < deadline:
        time.sleep(0.01)
    assert manager.cancel(job.id) is None
    assert manager.cancel("no-such-id") is None


def test_queue_lists_active_before_finished(tmp_path):
    manager = JobManager(workers=1)
    case_root = _case(tmp_path)
    started = threading.Event()
    release = threading.Event()

    def first_work(case, progress):
        started.set()
        release.wait(5)
        return "ok", None

    manager.submit(case_root, "c1", "analysis", "drain", first_work)
    assert started.wait(5)
    release.set()

    gate = threading.Event()

    def long_work(case, progress):
        gate.wait(5)
        return "ok", None

    running = manager.submit(case_root, "c1", "analysis", "long", long_work)
    deadline = time.time() + 5
    while running.status != "running" and time.time() < deadline:
        time.sleep(0.01)
    queued = manager.submit(case_root, "c1", "analysis", "queued",
                            lambda case, progress: ("ok", None))
    assert manager.cancel(queued.id) == "queued"  # cancelled while still waiting for the worker
    order = [j.id for j in manager.list()]
    assert order.index(running.id) < order.index(queued.id)
    gate.set()
