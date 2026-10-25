"""Manually repair/refresh the automatic local appointment mirror."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))
from app.db import engine
from app.file_mirror import write_snapshot
print("Saved appointments:", write_snapshot(engine))
