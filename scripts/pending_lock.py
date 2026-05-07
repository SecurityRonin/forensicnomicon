"""
pending_lock.py — shared lockfile helper for pending-review.md writers.

All scripts that read-modify-write (or append to) pending-review.md must use
locked_write() so they don't corrupt each other's changes.  The same convention
is used by:
  - fetch_all_sources.py  (imports from here)
  - check_feed_updates.py (imports from here)
  - review_loop.sh        (acquires path + ".lock" directly via shell)

Lock protocol:
  - Lock file: path + ".lock"
  - Lock file contains the owning PID as a plain integer string.
  - If the PID is dead (os.kill raises OSError), the lock is stolen.
  - File is written atomically via a temp file + os.replace().
"""

from __future__ import annotations

import os
import time
from typing import Callable


def locked_write(path: str, transform_fn: Callable[[str], str]) -> None:
    """Read-modify-write *path* under an exclusive advisory lockfile.

    Uses ``path + ".lock"`` as the lock.  The lockfile contains the writer's
    PID so stale locks from crashed processes are detected and stolen.

    *transform_fn* receives the current file content (empty string if the file
    does not exist) and returns the new content to write.  The write is
    performed atomically via a temp file + :func:`os.replace`.
    """
    lock_path = path + ".lock"

    # Acquire lock — spin with 0.1 s sleep until we own it or steal a dead one.
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            break  # we own the lock
        except FileExistsError:
            try:
                with open(lock_path) as lf:
                    pid_str = lf.read().strip()
                pid = int(pid_str)
                os.kill(pid, 0)  # raises OSError if process doesn't exist
                time.sleep(0.1)  # process alive — wait
            except (OSError, ValueError):
                # Dead PID or unreadable lockfile — steal it.
                try:
                    os.remove(lock_path)
                except OSError:
                    pass

    try:
        try:
            with open(path) as f:
                content = f.read()
        except OSError:
            content = ""

        new_content = transform_fn(content)

        tmp_path = path + ".tmp"
        with open(tmp_path, "w") as f:
            f.write(new_content)
        os.replace(tmp_path, path)
    finally:
        try:
            os.remove(lock_path)
        except OSError:
            pass
