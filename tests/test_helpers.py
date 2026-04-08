import shutil
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


@contextmanager
def workspace_temp_dir():
    root = Path(__file__).resolve().parent.parent / ".test_tmp"
    root.mkdir(parents=True, exist_ok=True)

    temp_dir = root / f"run_{uuid4().hex[:10]}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

