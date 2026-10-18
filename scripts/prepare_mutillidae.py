#!/usr/bin/env python3
"""Build reproducible, pinned Mutillidae source benchmark ZIPs.

The ZIPs are static-analysis sample sets, not runnable Mutillidae deployments.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import subprocess
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
SOURCE = DEMO / "mutillidae"
ARCHIVE = DEMO / "mutillidae-benchmark.zip"
_CROSSFILE_ARCHIVE = DEMO / "mutillidae-crossfile-benchmark.zip"
_MULTIFLOW_ARCHIVE = DEMO / "mutillidae-multiflow-benchmark.zip"
REPOSITORY = "https://github.com/webpwnized/mutillidae.git"
COMMIT = "126a1fdb4ff977f87e980d018f0def477afc3d5d"
FILES = {
    "mutillidae": (
        "LICENSE",
        "src/dns-lookup.php",
        "src/echo.php",
    ),
    "mutillidae-crossfile": (
        "LICENSE",
        "src/index.php",
        "src/user-info.php",
        "src/classes/SQLQueryHandler.php",
        "src/classes/MySQLHandler.php",
        "src/classes/EncodingHandler.php",
        "src/classes/CustomErrorHandler.php",
        "src/includes/constants.php",
        "src/includes/minimum-class-definitions.php",
    ),
    "mutillidae-multiflow": (
        "LICENSE",
        "src/index.php",
        "src/user-info.php",
        "src/register.php",
        "src/browser-info.php",
        "src/classes/SQLQueryHandler.php",
        "src/classes/MySQLHandler.php",
        "src/classes/EncodingHandler.php",
        "src/classes/CustomErrorHandler.php",
        "src/classes/ClientInformationHandler.php",
        "src/classes/CSRFTokenHandler.php",
        "src/includes/constants.php",
        "src/includes/minimum-class-definitions.php",
    ),
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(SOURCE), *args])


def ensure_source() -> None:
    if not SOURCE.exists():
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", REPOSITORY, str(SOURCE)],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(SOURCE), "fetch", "--depth", "1", "origin", COMMIT],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(SOURCE), "checkout", "--detach", COMMIT],
            check=True,
        )

    revision = git("rev-parse", "HEAD").decode().strip()
    if revision != COMMIT:
        raise SystemExit(
            f"Mutillidae HEAD is {revision}; expected {COMMIT}. Existing files were preserved."
        )
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise SystemExit("Mutillidae source has local changes; preserve them before preparing the ZIP.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--benchmark",
        choices=tuple(FILES),
        default="mutillidae",
    )
    args = parser.parse_args()

    DEMO.mkdir(exist_ok=True)
    ensure_source()
    selected_files = FILES[args.benchmark]
    archive_path = {
        "mutillidae": ARCHIVE,
        "mutillidae-crossfile": _CROSSFILE_ARCHIVE,
        "mutillidae-multiflow": _MULTIFLOW_ARCHIVE,
    }[args.benchmark]

    archive_bytes = git("archive", "--format=tar", COMMIT, *selected_files)
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as tar:
        for entry in tar:
            if not entry.isfile():
                continue
            stream = tar.extractfile(entry)
            if stream is None:
                raise SystemExit(f"Unable to read pinned source file: {entry.name}")
            contents[entry.name] = stream.read()

    if set(contents) != set(selected_files):
        raise SystemExit(f"Pinned archive did not contain the expected files: {sorted(contents)}")

    temporary = archive_path.with_suffix(".zip.tmp")
    try:
        with ZipFile(temporary, "w", compression=ZIP_DEFLATED) as archive:
            for name, data in sorted(contents.items()):
                entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                entry.compress_type = ZIP_DEFLATED
                archive.writestr(entry, data)
        temporary.replace(archive_path)
    finally:
        temporary.unlink(missing_ok=True)

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    print(f"Mutillidae commit: {COMMIT}")
    print(f"Included files: {', '.join(sorted(contents))}")
    print(f"Archive: {archive_path}")
    print(f"SHA256: {digest}")


if __name__ == "__main__":
    main()
