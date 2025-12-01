#!/usr/bin/env python3
"""Utility helpers for meercata Python port."""

import shutil
import subprocess
import sys
from typing import List, Optional


def run(cmd: List[str], apply: bool, stdin: Optional[str] = None, force: bool = False, ignore_errors: bool = False) -> bool:
    """Execute a command or print it when dry-run. force=True executes even in dry mode.

    Returns True on success (or when dry-run), False when execution failed.
    If ignore_errors is True, failure is swallowed and reported as False without printing.
    """
    if apply or force:
        try:
            stdout = subprocess.DEVNULL if ignore_errors else None
            stderr = subprocess.DEVNULL if ignore_errors else None
            subprocess.run(cmd, check=True, text=True, input=stdin, stdout=stdout, stderr=stderr)
            return True
        except subprocess.CalledProcessError as exc:
            if not ignore_errors:
                print(f"[ERR] command failed: {' '.join(cmd)} -> {exc}", file=sys.stderr)
            return False
    else:
        joined = " ".join(cmd)
        print(f"[DRY] {joined}")
        if stdin:
            print(stdin.rstrip())
        return True


def ensure_binaries(bins: List[str]) -> None:
    missing = [b for b in bins if not shutil.which(b)]
    if missing:
        print(f"[ERR] missing binaries: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)
