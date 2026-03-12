from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, TypeVar

from utils.logger import get_logger

log = get_logger(__name__)

T = TypeVar("T")
R = TypeVar("R")


def run_tasks(tasks: Iterable[T], worker: Callable[[T], R], max_workers: int = 4) -> List[R]:
    results: List[R] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(worker, task): task for task in tasks}
        for future in as_completed(future_map):
            task = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                log.exception("Task failed (%s): %s", task, exc)
    return results
