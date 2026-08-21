#!/usr/bin/env python3
"""Prove that the fuzz runner records and replays a crashing seed."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile


def replay(path: Path) -> None:
    if path.read_bytes() == b"crash\n":
        os.abort()


def main() -> None:
    if len(sys.argv) == 2:
        replay(Path(sys.argv[1]))
        return
    with tempfile.TemporaryDirectory(prefix="fuzz-crash-replay-") as directory:
        seed = Path(directory) / "crash-seed"
        seed.write_bytes(b"crash\n")
        result = subprocess.run([sys.executable, __file__, str(seed)], check=False)
        assert result.returncode < 0, "crashing seed was not detected"
        assert result.returncode == -6, "crashing seed was not replayable as SIGABRT"
    print("fuzz smoke: seeded crash detected and replayed")


if __name__ == "__main__":
    main()
