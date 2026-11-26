import os

BASE = "/var/data"


def write_report(filename: str, text: str) -> None:
    """Internal helper: the caller owns the filename."""
    path = os.path.join(BASE, filename)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
