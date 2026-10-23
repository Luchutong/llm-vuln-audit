#!/usr/bin/env python3
"""Build deployment, source and separate answer archives from the current tree."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import stat
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / 'VERSION').read_text().strip()
ANSWERS = ROOT.with_name('lab30-shop-answers')
OUT = ROOT.with_name('lab30-shop-releases') / VERSION
ALLOWED_ROOT = {'VERSION', 'README.md', 'compose.yaml', '.dockerignore'}
ALLOWED_DIRS = {'app', 'bin', 'docker', 'fixtures'}


def files():
    result = []
    for path in sorted(ROOT.rglob('*')):
        relative = path.relative_to(ROOT)
        if relative.parts[0] not in ALLOWED_DIRS and str(relative) not in ALLOWED_ROOT:
            continue
        if path.is_symlink():
            raise RuntimeError(f'Symlink is not allowed: {relative}')
        if path.is_file() and '__pycache__' not in relative.parts:
            result.append(path)
    return result


def archive(path, entries, manifest=None):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as output:
        for name, data, executable in entries:
            info = zipfile.ZipInfo(name, (2026, 10, 22, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | (0o755 if executable else 0o644)) << 16
            output.writestr(info, data)
        if manifest is not None:
            output.writestr('lab30-shop/release.json', json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')


def main():
    answer_paths = [ANSWERS / 'answers.json', ANSWERS / 'answers.md']
    if not all(path.is_file() for path in answer_paths):
        raise SystemExit('The two separate answer files must exist before packaging.')
    if (ROOT / 'app/VERSION').read_text().strip() != VERSION:
        raise SystemExit('Root and application versions must match.')
    selected = files()
    hashes = {str(path.relative_to(ROOT)): sha256(path.read_bytes()).hexdigest() for path in selected}
    tree_digest = sha256(''.join(f'{digest}  {name}\n' for name, digest in hashes.items()).encode()).hexdigest()
    images = {}
    for service in ('web', 'db', 'fixtures'):
        tag = f'lab30-shop-{service}:{VERSION}'
        images[tag] = subprocess.check_output(['docker', 'image', 'inspect', tag, '--format', '{{.Id}}'], text=True).strip()
    manifest = {
        'version': VERSION,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'upstream_commit': 'fcfd5b0283110cc5bb6e201ae5524804136e3659',
        'source_tree_sha256': tree_digest,
        'images': images,
        'files': hashes,
    }
    OUT.mkdir(parents=True, exist_ok=True)
    payload = [('lab30-shop/' + str(path.relative_to(ROOT)), path.read_bytes(), bool(path.stat().st_mode & 0o111)) for path in selected]
    artifacts = [OUT / f'lab30-shop-{VERSION}-source.zip', OUT / f'lab30-shop-{VERSION}-deploy.zip', OUT / f'lab30-shop-{VERSION}-answers.zip']
    archive(artifacts[0], payload)
    manifest['source_archive_sha256'] = sha256(artifacts[0].read_bytes()).hexdigest()
    archive(artifacts[1], payload, manifest)
    archive(artifacts[2], [('lab30-shop-answers/' + path.name, path.read_bytes(), False) for path in answer_paths])
    (OUT / 'release.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    (OUT / 'SHA256SUMS').write_text(''.join(f'{sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in artifacts))
    for path in artifacts:
        print(path)


if __name__ == '__main__':
    main()
