from pathlib import Path
from conftest import ROOT
SOURCE = ROOT / "src" / "qianshen"
TESTS = ROOT / "tests"
FORBIDDEN_IMPORTS = (
    "import requests", "import urllib", "import socket", "from http",
    "import psycopg", "import pymysql", "import sqlalchemy",
)

def python_files() -> list[Path]:
    return sorted(
        [*SOURCE.glob("*.py"), *TESTS.glob("*.py")],
        key=lambda path: path.as_posix(),
    )

def test_every_python_file_stays_under_300_lines():
    lengths = {path.relative_to(ROOT).as_posix(): len(path.read_text(encoding="utf-8").splitlines())
               for path in python_files()}
    assert lengths and max(lengths.values()) <= 300, lengths

def test_combined_source_and_test_size_is_in_required_range():
    total = sum(len(path.read_text(encoding="utf-8").splitlines()) for path in python_files())
    assert 2500 <= total <= 5500, total

def test_runtime_is_offline_and_inputs_are_synthetic():
    source_text = "\n".join(path.read_text(encoding="utf-8") for path in SOURCE.glob("*.py"))
    for needle in FORBIDDEN_IMPORTS:
        assert needle not in source_text
    corpus = source_text
    for path in [*(ROOT / "fixtures").rglob("*.sql"), *(ROOT / "fixtures").rglob("*.yml")]:
        corpus += path.read_text(encoding="utf-8")
    for needle in ("http://", "https://", "begin private key", "password="):
        assert needle not in corpus.lower()
