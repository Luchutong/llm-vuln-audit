#!/usr/bin/env python3
"""Prepare the pinned target and a reproducible ZIP without storing it in Git."""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
SOURCE = DEMO / "dvwa"
ARCHIVE = DEMO / "dvwa-source.zip"
COMMIT = "a96943dc1f52f390ee5df72144660636c4b7dd06"
REPOSITORY = "https://github.com/digininja/DVWA.git"


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(SOURCE), *args])


def main() -> None:
    DEMO.mkdir(exist_ok=True)
    if not SOURCE.exists():
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", "2.5", REPOSITORY, str(SOURCE)],
            check=True,
        )
    revision = git("rev-parse", "HEAD").decode().strip()
    if revision != COMMIT:
        raise SystemExit(f"DVWA HEAD is {revision}; expected {COMMIT}. Existing files were preserved.")
    if git("status", "--porcelain", "--untracked-files=all").strip():
        raise SystemExit("DVWA has local changes. Preserve them separately before preparing the demo.")

    # Match the demo's original scope: omit Git metadata/configuration, retain
    # every application file. The archive uses repository bytes, not local mtimes.
    contents: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(git("archive", "--format=tar", COMMIT))) as tar:
        for entry in tar:
            if any(part.startswith(".git") for part in Path(entry.name).parts):
                continue
            if entry.isdir():
                continue
            if not entry.isfile():
                raise SystemExit(f"Unsupported source entry: {entry.name}")
            stream = tar.extractfile(entry)
            assert stream is not None
            data = stream.read()
            if (SOURCE / entry.name).read_bytes() != data:
                raise SystemExit(f"Working source differs from pinned source: {entry.name}")
            contents[entry.name] = data

    if ARCHIVE.exists():
        with ZipFile(ARCHIVE) as archive:
            existing = {entry.filename: archive.read(entry) for entry in archive.infolist() if not entry.is_dir()}
        if existing != contents:
            raise SystemExit("Existing ZIP differs from the pinned source; it was preserved.")
    else:
        temporary = ARCHIVE.with_suffix(".zip.tmp")
        try:
            with ZipFile(temporary, "w", compression=ZIP_DEFLATED) as archive:
                for name, data in sorted(contents.items()):
                    entry = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.create_system = 3
                    entry.external_attr = 0o100644 << 16
                    entry.compress_type = ZIP_DEFLATED
                    archive.writestr(entry, data)
            temporary.replace(ARCHIVE)
        finally:
            temporary.unlink(missing_ok=True)

    manifest = {
        "repository": REPOSITORY,
        "commit": COMMIT,
        "archive_sha256": hashlib.sha256(ARCHIVE.read_bytes()).hexdigest(),
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(contents.items())},
    }
    (DEMO / "dvwa-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    print(f"DVWA {COMMIT}: {len(contents)} source files verified")
    print(f"Archive: {ARCHIVE}")
    print(f"SHA256: {manifest['archive_sha256']}")


if __name__ == "__main__":
    main()
