"""Immutable ZIP snapshots and bounded, read-only source tools.

Tree-sitter indexes PHP syntax, never a vulnerability filter. Every named function,
method and remaining script region is indexed, including code without sink hits.
Other languages are indexed as plain text lines so they can be searched, read and
cited as evidence without pretending to a symbol model they do not have. Original
files are kept byte-for-byte; cleaning only changes model projections.
"""
from __future__ import annotations

import bisect
from collections import OrderedDict
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import threading
import unicodedata
import uuid
import zipfile
from datetime import datetime, timezone

from tree_sitter import Language, Parser
import tree_sitter_php


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXTRACTED_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 40_000
MAX_COMPRESSION_RATIO = 1000
MAX_SLICE_LINES = 200
MAX_SLICE_BYTES = 16 * 1024
SLICE_OVERLAP_LINES = 24
MAX_READ_LINES = 400
MAX_READ_BYTES = 64 * 1024
# A whole project is the audit scope, so a search may have to sweep tens of
# thousands of files.  Cap how many are opened per call and report the shortfall
# instead of stalling the model on a silent full-tree scan.
MAX_SEARCH_FILES = 3_000
# Snapshot listings are bounded: a project can hold far more paths than a model,
# a report or a browser ever needs to enumerate inline.
MAX_LISTED_PATHS = 200
MAX_WARNINGS = 200
# The entry budget above is soft.  Safety validation (path traversal, symlinks,
# special files, collisions) still has to walk every entry, so an archive far past
# the budget is rejected outright rather than held in memory just to be trimmed.
MAX_SCANNED_ENTRIES = MAX_ENTRIES * 4
SCHEMA_VERSION = 2
# PHP projects in the wild still use versioned suffixes and PHP source includes.
# PHP keeps its tree-sitter symbol index; every other text file is imported as plain
# lines, so it can be searched, read and cited without a language model of its own.
PHP_EXTENSIONS = {".php", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".phps", ".inc", ".phtml"}
EXCLUDED_DIRECTORIES = {"vendor", "node_modules", "bower_components", "cache", "caches", "dist", "build", "coverage", "generated", ".git", ".hg", ".svn"}
# Dependency and build trees stay inside the snapshot: the whole project is the scope,
# and only the Planner's budget decides what gets read.  This set is navigation
# metadata (``dependency_tree``), never a filter.
DEPENDENCY_DIRECTORIES = EXCLUDED_DIRECTORIES | {
    "out", "target", ".venv", "venv", "__pycache__", ".next", ".nuxt", ".cache",
    ".gradle", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
}
LANGUAGE_BY_EXTENSION = {
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".php6": "php",
    ".php7": "php", ".php8": "php", ".phps": "php", ".inc": "php", ".phtml": "php",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".vue": "vue", ".svelte": "svelte",
    ".py": "python", ".rb": "ruby", ".go": "go", ".java": "java", ".kt": "kotlin",
    ".cs": "csharp", ".rs": "rust", ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".scala": "scala", ".pl": "perl", ".lua": "lua", ".r": "r",
    ".html": "html", ".htm": "html", ".xhtml": "html", ".twig": "template",
    ".tpl": "template", ".mustache": "template", ".hbs": "template", ".ejs": "template",
    ".css": "css", ".scss": "scss", ".sass": "sass", ".less": "less",
    ".json": "json", ".jsonc": "json", ".json5": "json", ".lock": "json",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".ini": "config", ".cfg": "config",
    ".conf": "config", ".properties": "config", ".env": "config", ".dist": "config",
    ".xml": "xml", ".xsd": "xml", ".xsl": "xml", ".svg": "xml", ".plist": "xml",
    ".sql": "sql", ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".fish": "shell",
    ".ps1": "powershell", ".bat": "batch", ".cmd": "batch",
    ".md": "markdown", ".markdown": "markdown", ".rst": "rst", ".adoc": "asciidoc",
    ".txt": "text", ".text": "text", ".log": "text", ".csv": "csv", ".tsv": "csv",
    ".diff": "diff", ".patch": "diff", ".map": "json", ".htaccess": "config",
}
# Suffixes whose bytes are never decoded as source.  Everything else falls back to a
# bounded NUL/UTF-8 probe, so an unknown extension is still readable when it is text.
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".whl", ".egg",
    ".pdf", ".ps", ".eps", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".ogg", ".webm", ".flac", ".mkv",
    ".so", ".dll", ".dylib", ".a", ".lib", ".o", ".obj", ".class", ".pyc", ".pyo", ".wasm",
    ".exe", ".bin", ".dat", ".db", ".sqlite", ".sqlite3", ".mdb", ".pdb",
    ".psd", ".ai", ".sketch", ".blend",
}
# Manifests, container files and server configuration describe how a project is wired
# together.  They are ordinary readable text; the role only helps navigation.
PROJECT_MANIFEST_NAMES = {
    "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock",
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "pom.xml",
    "build.gradle", "go.mod", "cargo.toml", "gemfile", "dockerfile", "docker-compose.yml",
    "docker-compose.yaml", "compose.yml", "compose.yaml", "makefile", ".env",
    ".env.example", ".env.dist", ".htaccess", "web.config", "nginx.conf", "httpd.conf",
}
# Root-level generic entry names.  Only the repository root counts, so these stay
# high-confidence orientation leads rather than turning every nested ``index.html``
# or bundled ``app.js`` into a fake request entrypoint.
GENERIC_ROOT_ENTRY_NAMES = {
    "index.html", "index.htm", "index.js", "index.ts", "app.js", "app.ts",
    "main.js", "main.ts", "app.py", "main.py", "wsgi.py", "asgi.py", "manage.py",
    "server.js", "server.ts", "server.py", "index.rb", "app.rb", "main.go",
}
SECURITY_COMMENT = re.compile(r"security|saniti|escap|validat|auth|csrf|inject|xss|sql|command|taint|input|password|whitelist|blacklist|用户|安全|漏洞|过滤|转义|验证|权限|密码", re.I)
PRIORITY_HINT = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|\b(?:mysqli_query|mysql_query|query|exec|system|shell_exec|passthru|echo|print)\b", re.I)
FUNCTION_TYPES = {"function_definition", "method_declaration"}
CLASS_TYPES = {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration", "anonymous_class"}
STRING_TYPES = {"string", "encapsed_string", "heredoc", "nowdoc", "text"}
INCLUDE_TYPES = {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}
CALL_TYPES = {"function_call_expression", "member_call_expression", "scoped_call_expression", "nullsafe_member_call_expression"}
# A suffixless/framework file needs an actual PHP opening tag before it is indexed.
# Support the standard long and echo forms plus the whitespace-delimited short form;
# deliberately exclude XML processing instructions such as ``<?xml``.
PHP_OPEN_TAG = re.compile(rb"<\?(?:php\b|=|(?=[\t\r\n ]))", re.I)

# Project-map roles are deliberately conservative.  A PHP parser's ``top_level``
# unit means only that text was not owned by a function or method; it is not proof
# that a web server or CLI invokes that file.  These path signals are used solely to
# select a small set of *high-confidence candidates* for initial project orientation.
# Workers still establish actual reachability by reading frozen source and any runtime
# configuration that is available to the audit.
ENTRY_INDEX_NAMES = {"index.php", "index.phtml", "index.phps"}
BOOTSTRAP_NAMES = {"bootstrap.php", "bootstrap.inc", "app.php", "application.php"}
CLI_ENTRY_NAMES = {"artisan", "console", "console.php", "cli.php", "server.php", "router.php"}
WEB_ROOT_DIRECTORIES = {"public", "web", "www", "htdocs", "httpdocs", "public_html"}
CLI_DIRECTORIES = {"bin", "cli"}
LIBRARY_DIRECTORIES = {"vendor", "lib", "libs", "library", "libraries", "include", "includes", "inc"}
TEST_DIRECTORIES = {"test", "tests", "spec", "specs", "fixture", "fixtures", "example", "examples"}
MATERIAL_DIRECTORIES = {"doc", "docs", "documentation", "help", "source", "sources", "sample", "samples"}
CONFIG_DIRECTORIES = {"config", "configs", "configuration", "settings"}
TEMPLATE_DIRECTORIES = {"template", "templates", "view", "views", "layout", "layouts"}
MODULE_CONTAINER_DIRECTORIES = {
    "modules", "module", "plugins", "plugin", "packages", "package", "apps", "app",
    "sites", "site", "extensions", "extension", "components", "component", "vulnerabilities",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value or ":" in value:
        raise ValueError("ZIP/source path is invalid")
    if value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise ValueError("ZIP/source path traversal or absolute path is forbidden")
    if len(value.encode("utf-8")) > 1024:
        raise ValueError("ZIP/source path is too long")
    return value


def _search_path(value: object) -> object:
    """Read the path a search was narrowed to, where the project root is spelled ".".

    A model writes the root as "", "." or "src/" as readily as it writes a bare path;
    left alone every one of those reaches ``_path`` as an empty or dot segment and is
    refused as a traversal.  A non-string is passed through so ``_path`` still rejects
    it with its own error.
    """
    if not isinstance(value, str):
        return value
    path = value.strip().rstrip("/")
    return path if path and path != "." else None


def _lines(data: bytes) -> list[bytes]:
    # Tree-sitter rows count LF, not Python's wider splitlines separator set.
    result = data.split(b"\n")
    if result and result[-1] == b"":
        result.pop()
    return result or [b""]


def _offsets(data: bytes) -> list[int]:
    return [0] + [match.end() for match in re.finditer(b"\n", data)]


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _position(start: int, end: int, offsets: list[int]) -> dict:
    first = bisect.bisect_right(offsets, start) - 1
    last = bisect.bisect_right(offsets, max(start, end - 1)) - 1
    return {"start_line": first + 1, "end_line": last + 1, "start_column": start - offsets[first], "end_column": end - offsets[last], "start_byte": start, "end_byte": end}


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _looks_like_php(content: bytes) -> bool:
    """Recognise PHP source files that use framework-specific or no suffix.

    File extensions remain a fast path, but projects such as Drupal commonly use
    `.module` / `.install` and CLI entrypoints can have no extension. PHP may begin
    after a long template or banner, so scan the whole bounded archive entry instead
    of only a prefix. Requiring an opening tag keeps arbitrary uploaded assets from
    being indexed as code while letting those valid PHP sources enter the same
    immutable snapshot workflow.
    """
    return PHP_OPEN_TAG.search(content) is not None


def _unknown_source_suffix(path: str) -> bool:
    """True when the suffix tables are silent about this name.

    ``_looks_like_php`` exists for framework-specific suffixes and extensionless
    entrypoints.  Applying it to a *known* other language instead turns any Python test
    or Markdown report that merely quotes a ``<?php`` sample into a PHP file, and the
    tree-sitter pass then harvests that file's ERROR nodes as its parse errors.
    """
    parsed = PurePosixPath(path)
    return (
        parsed.suffix.casefold() not in LANGUAGE_BY_EXTENSION
        and parsed.name.casefold() not in LANGUAGE_BY_EXTENSION
        and parsed.name.casefold() not in PROJECT_MANIFEST_NAMES
    )


def _line_count(data: bytes) -> int:
    """Count LF-delimited rows the way ``_lines`` does, without materialising them."""
    if not data:
        return 1
    return data.count(b"\n") + (0 if data.endswith(b"\n") else 1)


def _dependency_tree(path: str) -> bool:
    """True when any parent directory belongs to a dependency or build tree."""
    return any(part.casefold() in DEPENDENCY_DIRECTORIES for part in path.split("/")[:-1])


def _classify(content: bytes, path: str) -> tuple[str, str]:
    """Return ``(kind, language)`` for one archive entry.

    The file name and suffix tables are the fast path.  An unknown suffix is still
    text when the entry passes a bounded NUL probe and a bounded UTF-8 decode, so a
    project's odd-but-readable files stay searchable and citable.  Only entries that
    fail both probes become ``binary``: registered in the snapshot, never decoded.
    """
    parsed = PurePosixPath(path)
    name = parsed.name.casefold()
    suffix = parsed.suffix.casefold()
    if suffix in BINARY_EXTENSIONS or name in BINARY_EXTENSIONS:
        return "binary", "binary"
    # Dotfiles such as ``.env`` / ``.htaccess`` have no suffix, so match the name too.
    language = LANGUAGE_BY_EXTENSION.get(suffix) or LANGUAGE_BY_EXTENSION.get(name)
    if language is None and name in PROJECT_MANIFEST_NAMES:
        language = "config"
    if language is not None:
        return "text", language
    if b"\x00" in content[:8192]:
        return "binary", "binary"
    try:
        content[:65536].decode("utf-8")
    except UnicodeDecodeError:
        return "binary", "binary"
    return "text", "text"


def _project_path_profile(path: str) -> dict:
    """Classify a path for navigation without claiming runtime reachability.

    The result makes a useful distinction between likely request/command entry
    scripts and code that is normally included, configured, documented, or used as
    a test fixture.  It intentionally never promotes an unresolved static-include
    root or a parser ``top_level`` region to a high-confidence entrypoint.
    """
    parsed = PurePosixPath(path)
    name = parsed.name.casefold()
    directories = [part.casefold() for part in parsed.parts[:-1]]
    directory_set = set(directories)
    roles: set[str] = set()

    if directory_set & LIBRARY_DIRECTORIES:
        roles.add("library")
    if directory_set & TEST_DIRECTORIES:
        roles.add("test")
    if directory_set & MATERIAL_DIRECTORIES:
        roles.add("reference_material")
    if directory_set & CONFIG_DIRECTORIES or name.startswith(("config.", "settings.")):
        roles.add("configuration")
    if directory_set & TEMPLATE_DIRECTORIES:
        roles.add("template")
    if directory_set & WEB_ROOT_DIRECTORIES:
        roles.add("web_root")
    if directory_set & CLI_DIRECTORIES or name in CLI_ENTRY_NAMES:
        roles.add("cli")
    if "routes" in directory_set or "route" in directory_set:
        roles.add("route_definition")
    if "controller" in directory_set or "controllers" in directory_set:
        roles.add("controller")
    if "model" in directory_set or "models" in directory_set:
        roles.add("model")
    if "migration" in directory_set or "migrations" in directory_set:
        roles.add("migration")
    if "src" in directory_set:
        roles.add("application_code")
    if name in BOOTSTRAP_NAMES:
        roles.add("bootstrap")

    non_entry = bool(roles & {"library", "test", "reference_material", "configuration", "template"})
    entrypoint = None
    signals: list[str] = []
    # An index in a web/module directory and a root-level executable PHP script are
    # useful first places to orient an audit.  They remain candidates: framework
    # routing, rewrite rules and deployment configuration can still change reality.
    if not non_entry and name in ENTRY_INDEX_NAMES:
        if not directories:
            entrypoint = ("front_controller", 100)
            signals.append("root_index_name")
        elif directory_set & WEB_ROOT_DIRECTORIES:
            entrypoint = ("web_root_index", 95)
            signals.append("web_root_index_name")
        else:
            entrypoint = ("module_index", 80)
            signals.append("module_index_name")
    elif not non_entry and not directories and parsed.suffix.casefold() in PHP_EXTENSIONS:
        entrypoint = ("root_web_script", 85)
        signals.append("root_level_php_script")
    elif not non_entry and directory_set & WEB_ROOT_DIRECTORIES and parsed.suffix.casefold() in PHP_EXTENSIONS:
        entrypoint = ("web_root_script", 75)
        signals.append("web_root_php_script")
    elif not non_entry and (name in CLI_ENTRY_NAMES or directory_set & CLI_DIRECTORIES):
        entrypoint = ("cli_command", 70)
        signals.append("cli_name_or_directory")
    # A non-PHP project has no ``index.php``; a root-level framework entry such as
    # ``app.py``, ``server.js`` or ``wsgi.py`` is the equivalent orientation lead.
    # Only the repository root counts, so a bundled ``app.js`` deep inside a tree
    # never becomes a fake request entrypoint.
    elif not non_entry and not directories and name in GENERIC_ROOT_ENTRY_NAMES:
        entrypoint = ("root_generic_entry", 85)
        signals.append("root_generic_entry_name")

    if entrypoint:
        roles.add("entrypoint")
    return {
        "roles": sorted(roles),
        "non_entry": non_entry,
        "entrypoint": entrypoint,
        "signals": signals,
    }


# Orientation preference when a snapshot offers no entry or bootstrap candidate.
# Manifests and configuration describe how a project is wired together, then come
# application code and web roots, then everything else — always in a deterministic
# order so the same snapshot yields the same orientation reads.
_ORIENTATION_ROLE_RANK = ("configuration", "application_code", "web_root", "controller", "route_definition")


def _orientation_leads(project_map: dict, scope: set[str]) -> list[str]:
    """Rank readable files as orientation leads when no entrypoint exists."""
    ranked = []
    for row in project_map.get("files") or []:
        path = str(row.get("path") or "")
        if path not in scope:
            continue
        name = PurePosixPath(path).name.casefold()
        if name in PROJECT_MANIFEST_NAMES:
            rank = 0
        else:
            roles = set(row.get("roles") or [])
            rank = next(
                (index + 1 for index, role in enumerate(_ORIENTATION_ROLE_RANK) if role in roles),
                len(_ORIENTATION_ROLE_RANK) + 1,
            )
        ranked.append((rank, bool(row.get("dependency_tree")), path))
    ranked.sort()
    return [path for _, _, path in ranked]


def _project_module_path(path: str) -> str:
    """Return a stable, shallow grouping key for an arbitrary PHP tree."""
    directories = list(PurePosixPath(path).parts[:-1])
    if not directories:
        return "."
    if directories[0].casefold() in MODULE_CONTAINER_DIRECTORIES and len(directories) > 1:
        return "/".join(directories[:2])
    return directories[0]


class SourceRepository:
    def __init__(self, storage: Path):
        self.storage = Path(storage)
        self.snapshots = self.storage / "snapshots"
        self.snapshots.mkdir(parents=True, exist_ok=True)
        self.parser = Parser(Language(tree_sitter_php.language_php()))
        self._parser_lock = threading.Lock()
        # A whole-project snapshot is megabytes of JSON and every tool call needs a
        # slice of it.  Publication is atomic and snapshot files are read-only, so an
        # mtime check keeps a small LRU honest.  Not ``lru_cache`` on a method: that
        # would pin ``self`` for the process lifetime.
        self._cache_lock = threading.Lock()
        self._snapshot_cache: OrderedDict[str, tuple[int, dict, dict]] = OrderedDict()
        self._syntax_cache: OrderedDict[str, tuple[int, dict]] = OrderedDict()
        self._cache_limit = 4

    def _directory(self, snapshot_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", snapshot_id or ""):
            raise FileNotFoundError("Snapshot does not exist")
        directory = self.snapshots / snapshot_id
        if not (directory / "index.json").is_file():
            raise FileNotFoundError("Snapshot does not exist")
        return directory

    def _cached(self, snapshot_id: str) -> tuple[dict, dict]:
        """Return ``(snapshot, records_by_path)`` for a published snapshot."""
        directory = self._directory(snapshot_id)
        stamp = (directory / "index.json").stat().st_mtime_ns
        with self._cache_lock:
            hit = self._snapshot_cache.get(snapshot_id)
            if hit is not None and hit[0] == stamp:
                self._snapshot_cache.move_to_end(snapshot_id)
                return hit[1], hit[2]
        snapshot = json.loads((directory / "index.json").read_text("utf-8"))
        records = {item["path"]: item for item in snapshot.get("files") or []}
        with self._cache_lock:
            self._snapshot_cache[snapshot_id] = (stamp, snapshot, records)
            self._snapshot_cache.move_to_end(snapshot_id)
            while len(self._snapshot_cache) > self._cache_limit:
                self._snapshot_cache.popitem(last=False)
        return snapshot, records

    def get_snapshot(self, snapshot_id: str) -> dict:
        return self._cached(snapshot_id)[0]

    def syntax_index(self, snapshot_id: str) -> dict:
        """Return the PHP symbol index, parsed at most once per published snapshot."""
        path = self._directory(snapshot_id) / "syntax.json"
        stamp = path.stat().st_mtime_ns
        with self._cache_lock:
            hit = self._syntax_cache.get(snapshot_id)
            if hit is not None and hit[0] == stamp:
                self._syntax_cache.move_to_end(snapshot_id)
                return hit[1]
        syntax = json.loads(path.read_text("utf-8"))
        with self._cache_lock:
            self._syntax_cache[snapshot_id] = (stamp, syntax)
            self._syntax_cache.move_to_end(snapshot_id)
            while len(self._syntax_cache) > self._cache_limit:
                self._syntax_cache.popitem(last=False)
        return syntax

    def import_zip(self, data: bytes, filename: str) -> dict:
        if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_BYTES:
            raise ValueError(f"ZIP exceeds the {MAX_ARCHIVE_BYTES // (1024 * 1024)} MiB upload limit")
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError) as exc:
            raise ValueError("Invalid ZIP archive") from exc
        staging = Path(tempfile.mkdtemp(prefix=".import-", dir=self.snapshots))
        try:
            with archive:
                entries = archive.infolist()
                if len(entries) > MAX_SCANNED_ENTRIES:
                    raise ValueError(f"ZIP contains too many entries ({len(entries)} > {MAX_SCANNED_ENTRIES})")
                # Safety properties stay hard rejects.  Only capacity limits downgrade
                # to a per-entry skip with a warning: one oversized asset or one
                # pathological entry must not fail an otherwise importable project.
                accepted: dict[str, zipfile.ZipInfo] = {}
                normalized: dict[str, bool] = {}
                for entry in entries:
                    # orig_filename retains NULs that ZipInfo.filename truncates.
                    original = entry.orig_filename
                    name = _path(original[:-1] if original.endswith("/") else original)
                    key = unicodedata.normalize("NFC", name).casefold()
                    if key in normalized:
                        raise ValueError(f"ZIP contains colliding paths: {name}")
                    normalized[key] = entry.is_dir()
                    mode = entry.external_attr >> 16
                    file_type = stat.S_IFMT(mode)
                    if stat.S_ISLNK(mode):
                        raise ValueError("ZIP symbolic links are forbidden")
                    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                        raise ValueError("ZIP special files are forbidden")
                    if entry.flag_bits & 1:
                        raise ValueError("Encrypted ZIP entries are unsupported")
                    if not entry.is_dir():
                        accepted[name] = entry
                for name in accepted:
                    key = unicodedata.normalize("NFC", name).casefold()
                    for parent in PurePosixPath(key).parents:
                        if str(parent) != "." and normalized.get(str(parent)) is False:
                            raise ValueError(f"ZIP file/directory collision: {name}")
                # Budgets are applied in path order so that which entries a given ZIP
                # loses is reproducible rather than an artefact of central-directory order.
                skipped: list[dict] = []
                candidates = sorted(accepted)
                if len(candidates) > MAX_ENTRIES:
                    for name in candidates[MAX_ENTRIES:]:
                        skipped.append({"path": name, "reason": "entry_limit", "detail": f"archive holds more than {MAX_ENTRIES} files"})
                    candidates = candidates[:MAX_ENTRIES]
                usable = []
                for name in candidates:
                    entry = accepted[name]
                    if entry.file_size > MAX_FILE_BYTES:
                        skipped.append({"path": name, "reason": "file_too_large", "detail": f"{entry.file_size} bytes exceeds the {MAX_FILE_BYTES} byte per-file limit"})
                        continue
                    if entry.file_size / max(1, entry.compress_size) > MAX_COMPRESSION_RATIO:
                        skipped.append({"path": name, "reason": "compression_ratio", "detail": f"ratio exceeds {MAX_COMPRESSION_RATIO}; entry not expanded"})
                        continue
                    usable.append(name)
                snapshot_id = uuid.uuid4().hex
                digest = _sha(data)
                sources = staging / "sources"
                sources.mkdir()
                files, units, syntax, warnings = [], [], {}, []
                extracted = 0
                for name in usable:
                    entry = accepted[name]
                    with archive.open(entry) as handle:
                        content = handle.read(MAX_FILE_BYTES + 1)
                    if len(content) != entry.file_size or len(content) > MAX_FILE_BYTES:
                        skipped.append({"path": name, "reason": "size_mismatch", "detail": "decompressed size does not match the archive directory"})
                        continue
                    extracted += len(content)
                    if extracted > MAX_EXTRACTED_BYTES:
                        raise ValueError(f"ZIP exceeds the {MAX_EXTRACTED_BYTES // (1024 * 1024)} MiB extraction limit")
                    destination = sources / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    kind, language = _classify(content, name)
                    reason = next((part for part in PurePosixPath(name).parts[:-1] if part.casefold() in EXCLUDED_DIRECTORIES), None)
                    is_php = (
                        PurePosixPath(name).suffix.casefold() in PHP_EXTENSIONS
                        or (kind == "text" and _unknown_source_suffix(name) and _looks_like_php(content))
                    )
                    record = {"path": name, "sha256": _sha(content), "size": len(content), "line_count": _line_count(content), "excluded": bool(reason) or not is_php, "exclude_reason": f"Default dependency/generated directory: {reason}" if reason else (None if is_php else "Not a PHP source file"), "is_php": is_php, "kind": kind, "language": language, "dependency_tree": _dependency_tree(name), "parse_errors": []}
                    # Only text entries are ever decoded for display; warning about a
                    # PNG or a nested archive not being UTF-8 is noise, not a finding.
                    if kind == "text":
                        try:
                            content.decode("utf-8")
                        except UnicodeDecodeError:
                            record["encoding_warning"] = "Not valid UTF-8; display uses replacement characters; original bytes preserved"
                            warnings.append(f"{name}: display decoding contains replacement characters")
                    # ``_index`` needs real PHP syntax nodes; running it on another
                    # language would only harvest ERROR nodes as fake parse errors.
                    if is_php:
                        file_units, file_syntax, errors = self._index(content, name, digest, snapshot_id)
                        record["parse_errors"] = errors
                        syntax[name] = file_syntax
                        units.extend(file_units)
                        if errors:
                            warnings.append(f"{name}: PHP parse errors; indexed units require context review")
                    files.append(record)
                files.sort(key=lambda item: item["path"])
                languages: dict[str, int] = {}
                for record in files:
                    languages[record["language"]] = languages.get(record["language"], 0) + 1
                excluded = [record["path"] for record in files if record["excluded"]]
                if skipped:
                    warnings.append(f"{len(skipped)} files were skipped at import and are not in this snapshot; see skipped_files for each reason")
                if len(warnings) > MAX_WARNINGS:
                    warnings = warnings[:MAX_WARNINGS] + [f"{len(warnings) - MAX_WARNINGS} further import warnings omitted; see skipped_files and files for details"]
                snapshot = {
                    "id": snapshot_id,
                    "schema_version": SCHEMA_VERSION,
                    "name": PurePosixPath(str(filename).replace("\\", "/")).name[:200],
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "archive_sha256": digest,
                    "source": "uploaded_zip",
                    "files": files,
                    "units": sorted(units, key=lambda item: (-item["priority"], item["file_path"], item["start_byte"])),
                    "warnings": warnings,
                    "immutable": True,
                    "import_limits": {"archive_bytes": MAX_ARCHIVE_BYTES, "extracted_bytes": MAX_EXTRACTED_BYTES, "file_bytes": MAX_FILE_BYTES, "entries": MAX_ENTRIES, "compression_ratio": MAX_COMPRESSION_RATIO},
                    "stats": {
                        "files": len(files),
                        "text_files": sum(1 for record in files if record["kind"] == "text"),
                        "binary_files": sum(1 for record in files if record["kind"] == "binary"),
                        "php_files": sum(1 for record in files if record["is_php"]),
                        "dependency_tree_files": sum(1 for record in files if record["dependency_tree"]),
                        "languages": dict(sorted(languages.items(), key=lambda item: (-item[1], item[0]))),
                        "skipped_count": len(skipped),
                        "excluded_count": len(excluded),
                    },
                    "excluded_files": excluded[:MAX_LISTED_PATHS],
                    "skipped_files": skipped[:MAX_LISTED_PATHS],
                }
                (staging / "archive.zip").write_bytes(data)
                (staging / "syntax.json").write_text(json.dumps(syntax, ensure_ascii=False), "utf-8")
                (staging / "index.json").write_text(json.dumps(snapshot, ensure_ascii=False), "utf-8")
                # Only a completely indexed snapshot becomes visible. Files are made
                # read-only as an additional guard; no API offers mutation.
                for path in staging.rglob("*"):
                    if path.is_file():
                        path.chmod(0o444)
                os.replace(staging, self.snapshots / snapshot_id)
                return snapshot
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, OSError) as exc:
            raise ValueError(f"ZIP import failed: {exc}") from exc
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    def _index(self, content: bytes, path: str, digest: str, snapshot_id: str):
        with self._parser_lock:
            tree = self.parser.parse(content)
        nodes = list(_walk(tree.root_node))
        offsets = _offsets(content)
        # Missing punctuation is often an unnamed node, so a named-node walk
        # alone would incorrectly hide some syntax failures.
        error_nodes = []
        pending = [tree.root_node]
        while pending:
            node = pending.pop()
            if node.type == "ERROR" or node.is_missing:
                error_nodes.append(node)
            pending.extend(child for child in node.children if child.has_error or child.is_missing or child.type == "ERROR")
        errors = [{"type": "missing" if node.is_missing else "error", **_position(node.start_byte, max(node.start_byte + 1, node.end_byte), offsets), "text": _decode(content[node.start_byte:node.end_byte])[:300]} for node in error_nodes]
        if tree.root_node.has_error and not errors:
            errors.append({"type": "error", "start_line": 1, "end_line": len(_lines(content)), "text": "Parser reports an unresolved syntax error"})
        syntax = {"functions": [], "classes": [], "includes": [], "calls": []}
        spans = []
        for node in nodes:
            if node.type in FUNCTION_TYPES:
                name_node = node.child_by_field_name("name")
                name = _decode(content[name_node.start_byte:name_node.end_byte]) if name_node else "<anonymous>"
                ancestor = node.parent
                class_name = None
                while ancestor:
                    if ancestor.type in CLASS_TYPES:
                        class_node = ancestor.child_by_field_name("name")
                        class_name = _decode(content[class_node.start_byte:class_node.end_byte]) if class_node else "<anonymous class>"
                        break
                    ancestor = ancestor.parent
                symbol = f"{class_name}::{name}" if node.type == "method_declaration" and class_name else name
                record = {"name": name, "symbol": symbol, "class_name": class_name, **_position(node.start_byte, node.end_byte, offsets)}
                syntax["functions"].append(record)
                spans.append({"start": node.start_byte, "end": node.end_byte, "symbol": symbol, "kind": "method" if node.type == "method_declaration" else "function", "class_name": class_name})
            elif node.type in CLASS_TYPES:
                name_node = node.child_by_field_name("name")
                body = node.child_by_field_name("body")
                syntax["classes"].append({"name": _decode(content[name_node.start_byte:name_node.end_byte]) if name_node else "<anonymous class>", **_position(node.start_byte, node.end_byte, offsets), "header_end_line": body.start_point.row + 1 if body else node.start_point.row + 1})
            elif node.type in INCLUDE_TYPES:
                syntax["includes"].append({"expression": _decode(content[node.start_byte:node.end_byte]), **_position(node.start_byte, node.end_byte, offsets)})
            elif node.type in CALL_TYPES:
                callee = node.child_by_field_name("function") or node.child_by_field_name("name")
                syntax["calls"].append({"name": _decode(content[callee.start_byte:callee.end_byte]) if callee else "<dynamic>", "expression": _decode(content[node.start_byte:node.end_byte])[:300], **_position(node.start_byte, node.end_byte, offsets)})
        # Complement of outermost named functions/methods retains top-level code,
        # templates, class initializers, and exact partial-line coordinates.
        covered = []
        for span in sorted(spans, key=lambda item: (item["start"], -item["end"])):
            if covered and span["start"] <= covered[-1][1]:
                covered[-1] = (covered[-1][0], max(covered[-1][1], span["end"]))
            else:
                covered.append((span["start"], span["end"]))
        cursor = 0
        for start, end in covered + [(len(content), len(content))]:
            if start > cursor:
                fragment = content[cursor:start]
                meaningful = re.sub(rb"<\?(?:php|=)?|\?>|[\s{};]", b"", fragment)
                if meaningful:
                    spans.append({"start": cursor, "end": start, "symbol": "<top-level>", "kind": "top_level", "class_name": None})
            cursor = max(cursor, end)
        if not spans:
            spans.append({"start": 0, "end": len(content), "symbol": "<top-level>", "kind": "top_level", "class_name": None})
        comments = [(node.start_byte, node.end_byte, bool(SECURITY_COMMENT.search(_decode(content[node.start_byte:node.end_byte])))) for node in nodes if node.type == "comment"]
        protected = [(node.start_byte, node.end_byte) for node in nodes if node.type in STRING_TYPES]
        boundaries = set()
        for node in nodes:
            if node.type.endswith("_statement") or node.type in FUNCTION_TYPES | {"text_interpolation", "property_declaration"}:
                end = node.end_byte
                newline = content.find(b"\n", end)
                if newline != -1 and not content[end:newline].strip():
                    end = newline + 1
                boundaries.add(end)
        units = []
        for span in spans:
            chunks = self._slice(content, span["start"], span["end"], offsets, sorted(boundaries))
            for number, (start, end, rule) in enumerate(chunks):
                position = _position(start, end, offsets)
                cleaned, omissions = self._clean(content, start, end, offsets, comments, protected)
                identity = f"{digest}:{path}:{span['kind']}:{span['start']}:{span['end']}:{start}:{end}"
                units.append({"id": _sha(identity.encode())[:32], "snapshot_id": snapshot_id, "file_path": path, **position, "symbol": span["symbol"], "kind": span["kind"], "class_name": span["class_name"], "priority": len(PRIORITY_HINT.findall(_decode(content[start:end]))), "slice_index": number + 1, "slice_count": len(chunks), "parent_start_byte": span["start"], "parent_end_byte": span["end"], "cleaned_lines": cleaned, "omissions": omissions, "slice_rule": rule, "parse_incomplete": bool(errors), "checklist": ["sqli", "xss_r", "command_injection"], "status": "pending"})
        return units, syntax, errors

    @staticmethod
    def _slice(content: bytes, start: int, end: int, offsets: list[int], boundaries: list[int]):
        result = []
        cursor = start
        if cursor == end:
            return [(start, end, {"max_lines": MAX_SLICE_LINES, "max_bytes": MAX_SLICE_BYTES, "overlap_lines": 0, "boundary": "unit_end"})]
        while cursor < end:
            row = bisect.bisect_right(offsets, cursor) - 1
            line_limit = offsets[row + MAX_SLICE_LINES] if row + MAX_SLICE_LINES < len(offsets) else end
            limit = min(end, cursor + MAX_SLICE_BYTES, line_limit)
            boundary = "unit_end"
            stop = limit
            if limit < end:
                candidates = [point for point in boundaries if cursor < point <= limit]
                if candidates:
                    stop, boundary = candidates[-1], "statement_boundary"
                else:
                    last_lf = content.rfind(b"\n", cursor, limit)
                    stop = last_lf + 1 if last_lf >= cursor else limit
                    boundary = "forced_line_boundary" if last_lf >= cursor else "forced_byte_boundary"
                    # Never split a UTF-8 sequence; original bytes stay untouched.
                    while stop > cursor and stop < len(content) and content[stop] & 0xC0 == 0x80:
                        stop -= 1
            stop = max(cursor + 1, stop)
            last_row = bisect.bisect_right(offsets, stop - 1) - 1
            if stop < end and last_row - row + 1 > SLICE_OVERLAP_LINES:
                next_cursor = max(cursor + 1, offsets[last_row - SLICE_OVERLAP_LINES + 1])
            elif stop < end and boundary == "forced_byte_boundary":
                next_cursor = stop - min(1024, (stop - cursor) // 4)
                while next_cursor < stop and content[next_cursor] & 0xC0 == 0x80:
                    next_cursor += 1
            else:
                next_cursor = stop
            overlap = last_row - (bisect.bisect_right(offsets, next_cursor) - 1) + 1 if next_cursor < stop else 0
            result.append((cursor, stop, {"max_lines": MAX_SLICE_LINES, "max_bytes": MAX_SLICE_BYTES, "overlap_lines": overlap, "boundary": boundary, "context_required": boundary.startswith("forced_")}))
            cursor = next_cursor
        return result

    @staticmethod
    def _clean(content, start, end, offsets, comments, protected):
        rows, omitted = [], []
        first = bisect.bisect_right(offsets, start) - 1
        last = bisect.bisect_right(offsets, max(start, end - 1)) - 1
        for row in range(first, last + 1):
            line_start = max(start, offsets[row])
            line_end = min(end, offsets[row + 1] if row + 1 < len(offsets) else len(content))
            segment = content[line_start:line_end].rstrip(b"\r\n")
            mutable = bytearray(segment)
            for comment_start, comment_end, security in comments:
                if not security and comment_start < line_end and comment_end > line_start:
                    left, right = max(0, comment_start - line_start), min(len(mutable), comment_end - line_start)
                    if right > left:
                        mutable[left:right] = b" " * (right - left)
                        omitted.append({"start_line": row + 1, "end_line": row + 1, "start_column": comment_start - offsets[row] if comment_start >= offsets[row] else 0, "reason": "irrelevant_comment"})
            in_literal = any(left < line_end and right > line_start for left, right in protected)
            if not mutable.strip() and not in_literal:
                if segment.strip() == b"":
                    omitted.append({"start_line": row + 1, "end_line": row + 1, "reason": "blank_line"})
                continue
            rows.append({"number": row + 1, "text": _decode(bytes(mutable)), "start_column": line_start - offsets[row], "end_column": line_start - offsets[row] + len(segment)})
        return rows, omitted

    def _content(self, snapshot_id: str, path: str):
        path = _path(path)
        _, records = self._cached(snapshot_id)
        record = records.get(path)
        if record is None:
            raise FileNotFoundError("Source file does not exist in snapshot")
        if record.get("kind") == "binary":
            raise ValueError("Binary file is registered in the snapshot but cannot be decoded; use the archive for its bytes")
        content = (self._directory(snapshot_id) / "sources" / path).read_bytes()
        if _sha(content) != record["sha256"]:
            raise ValueError("Snapshot integrity check failed")
        return content, record

    def read_source(self, snapshot_id: str, path: str, start: int = 1, end: int = 200) -> dict:
        if isinstance(start, bool) or isinstance(end, bool) or not isinstance(start, int) or not isinstance(end, int) or start < 1 or end < start or end - start + 1 > MAX_READ_LINES:
            raise ValueError("Source range must contain 1 to 400 lines with positive line numbers")
        content, record = self._content(snapshot_id, path)
        original = _lines(content)
        if start > len(original):
            raise ValueError("Source start line exceeds file length")
        result, used = [], 0
        for number in range(start, min(end, len(original)) + 1):
            line = original[number - 1].rstrip(b"\r")
            size = len(line) + 1
            if used + size > MAX_READ_BYTES:
                if not result:
                    raise ValueError("Source line exceeds 64 KiB tool output; use indexed byte slices")
                break
            used += size
            result.append({"number": number, "text": _decode(line)})
        actual_end = result[-1]["number"] if result else start
        return {"snapshot_id": snapshot_id, "path": path, "sha256": record["sha256"], "lines": result, "start_line": start, "end_line": actual_end, "truncated": actual_end < min(end, len(original)), "next_start": actual_end + 1 if actual_end < min(end, len(original)) else None}

    def search_code(
        self,
        snapshot_id: str,
        query: str,
        path: str | None = None,
        limit: int = 40,
        *,
        allowed_paths: set[str] | None = None,
        include_dependencies: bool = False,
    ) -> dict:
        if not isinstance(query, str) or not query or len(query) > 200 or "\n" in query or "\r" in query:
            raise ValueError("Search query must be a nonempty literal of at most 200 characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("Search limit must be between 1 and 100")
        _, records = self._cached(snapshot_id)
        allowed = set(allowed_paths) if allowed_paths is not None else None
        if allowed is not None:
            unknown_allowed = allowed - set(records)
            if unknown_allowed:
                raise ValueError("Source access policy contains files outside the snapshot")
        path = _search_path(path)
        if path is not None:
            path = _path(path)
            if path in records:
                if allowed is not None and path not in allowed:
                    raise ValueError("Source path is outside this task's frozen scope")
                if records[path].get("kind") == "binary":
                    raise ValueError("Binary file is registered in the snapshot but cannot be searched")
                candidates = [records[path]]
            else:
                # A directory narrows the search instead of failing.  Callers ask for
                # "the files under this tree" far more often than they guess a file, and
                # a directory always raised here, so no working call changes meaning.
                prefix = path.rstrip("/") + "/"
                subtree = [
                    record for record in records.values() if record["path"].startswith(prefix)
                ]
                if not subtree:
                    raise FileNotFoundError("Source file or directory does not exist in snapshot")
                candidates = [
                    record for record in subtree
                    if record.get("kind") != "binary"
                    and (allowed is None or record["path"] in allowed)
                    and (include_dependencies or not record.get("dependency_tree"))
                ]
                candidates.sort(key=lambda record: (bool(record.get("dependency_tree")), record["path"]))
        else:
            # A whole-project scope means a search may sweep tens of thousands of
            # files, so the candidate set is explicit, deterministically ordered and
            # bounded; the shortfall is reported instead of stalling the model.
            candidates = [
                record for record in records.values()
                if record.get("kind") != "binary"
                and (allowed is None or record["path"] in allowed)
                and (include_dependencies or not record.get("dependency_tree"))
            ]
            candidates.sort(key=lambda record: (bool(record.get("dependency_tree")), record["path"]))
        scan_truncated = len(candidates) > MAX_SEARCH_FILES
        if scan_truncated:
            candidates = candidates[:MAX_SEARCH_FILES]
        matches, size, truncated, scanned = [], 0, False, 0
        directory = self._directory(snapshot_id) / "sources"
        for file in candidates:
            scanned += 1
            # Avoid reloading/scanning a potentially large index for each file.
            content = (directory / file["path"]).read_bytes()
            if _sha(content) != file["sha256"]:
                raise ValueError("Snapshot integrity check failed")
            for number, raw in enumerate(_lines(content), 1):
                line = _decode(raw.rstrip(b"\r"))
                if query not in line:
                    continue
                if len(matches) >= limit or size + len(raw) > MAX_READ_BYTES:
                    truncated = True
                    break
                size += len(raw)
                matches.append({"snapshot_id": snapshot_id, "path": file["path"], "line": number, "number": number, "text": line, "sha256": file["sha256"]})
            if truncated:
                break
        return {
            "snapshot_id": snapshot_id,
            "query": query,
            "matches": matches,
            "truncated": truncated or scan_truncated,
            "scanned_files": scanned,
            "scan_limit": MAX_SEARCH_FILES,
            "scan_truncated": scan_truncated,
            "include_dependencies": bool(include_dependencies),
        }

    @staticmethod
    def _resolve_include(expression: str, path: str, available: set[str]) -> str | None:
        expression = re.sub(r"^(?:include|require)(?:_once)?\s*", "", expression).strip().rstrip(";")
        if expression.startswith("(") and expression.endswith(")"):
            expression = expression[1:-1].strip()
        # Evaluate only literal concatenation and known file/directory constants.
        pieces = re.findall(r"(?:'[^']*'|\"[^\"]*\"|__DIR__|dirname\s*\(\s*__FILE__\s*\))", expression)
        residue = re.sub(r"(?:'[^']*'|\"[^\"]*\"|__DIR__|dirname\s*\(\s*__FILE__\s*\))", "", expression)
        if residue.replace(".", "").strip() or not pieces:
            return None
        parent = str(PurePosixPath(path).parent)
        resolved = "".join(parent if piece == "__DIR__" or piece.startswith("dirname") else piece[1:-1] for piece in pieces)
        if resolved.startswith("/") or "$" in resolved or "\\" in resolved or ":" in resolved:
            return None
        candidates = [resolved] if any(piece == "__DIR__" or piece.startswith("dirname") for piece in pieces) else [f"{parent}/{resolved}", resolved]
        for candidate in candidates:
            parts = []
            for part in candidate.split("/"):
                if part in {"", "."}:
                    continue
                if part == "..":
                    if not parts:
                        break
                    parts.pop()
                else:
                    parts.append(part)
            else:
                normalized = "/".join(parts)
                if normalized in available:
                    return normalized
        return None

    def get_context(
        self,
        snapshot_id: str,
        unit: dict,
        *,
        allowed_paths: set[str] | None = None,
    ) -> dict:
        snapshot = self.get_snapshot(snapshot_id)
        owned = next((item for item in snapshot["units"] if item["id"] == unit.get("id")), None)
        if owned is None:
            raise ValueError("Audit unit does not belong to snapshot")
        syntax = self.syntax_index(snapshot_id)
        path = owned["file_path"]
        allowed_scope = set(allowed_paths) if allowed_paths is not None else None
        if allowed_scope is not None and path not in allowed_scope:
            raise ValueError("Audit unit is outside this task's frozen scope")
        # Only PHP files carry a syntax index; other languages are read as plain lines.
        current = syntax.get(path)
        if current is None:
            raise ValueError("This file has no PHP syntax index; read it with read_source instead")
        available = {item["path"] for item in snapshot["files"] if item.get("kind") != "binary"}
        requests, unresolved = [], []
        for item in current["classes"]:
            if item["start_byte"] <= owned["start_byte"] and item["end_byte"] >= owned["end_byte"]:
                requests.append((path, item["start_line"], min(item["header_end_line"] + 20, item["end_line"]), "owning_class"))
        for item in current["includes"]:
            requests.append((path, item["start_line"], item["end_line"], "include_statement"))
            resolved = self._resolve_include(item["expression"], path, available)
            if resolved:
                requests.append((resolved, 1, 120, "included_file"))
            else:
                unresolved.append({"path": path, "line": item["start_line"], "expression": item["expression"], "reason": "Dynamic, external, or missing include; static context cannot resolve"})
        calls = {item["name"].casefold() for item in current["calls"] if owned["parent_start_byte"] <= item["start_byte"] < owned["parent_end_byte"]}
        for other_path, index in syntax.items():
            for function in index["functions"]:
                if function["name"].casefold() in calls:
                    requests.append((other_path, function["start_line"], min(function["end_line"], function["start_line"] + 119), "related_function"))
            for call in index["calls"]:
                name = owned["symbol"].split("::")[-1].casefold()
                if name != "<top-level>" and call["name"].casefold() == name:
                    requests.append((other_path, max(1, call["start_line"] - 4), call["end_line"] + 4, "call_location"))
            for include in index["includes"]:
                if self._resolve_include(include["expression"], other_path, available) == path:
                    requests.append((other_path, 1, 120, "including_entrypoint"))
        # Adjacent entry scripts often choose a security-level file dynamically.
        for parent in [PurePosixPath(path).parent, *list(PurePosixPath(path).parent.parents)[:3]]:
            entry = str(parent / "index.php")
            if entry in available and entry != path:
                requests.append((entry, 1, 120, "nearby_entrypoint"))
        excerpts, seen, used = [], set(), 0
        for context_path, start, end, reason in requests:
            key = (context_path, start, end)
            if key in seen:
                continue
            seen.add(key)
            if allowed_scope is not None and context_path not in allowed_scope:
                unresolved.append({
                    "path": context_path,
                    "line": start,
                    "reason": "Related source is outside this task's frozen scope",
                })
                continue
            if len(excerpts) >= 12 or used >= 32 * 1024:
                unresolved.append({"path": context_path, "line": start, "reason": "Context tool output budget reached; use read_source"})
                continue
            try:
                excerpt = self.read_source(snapshot_id, context_path, start, end)
            except ValueError as exc:
                unresolved.append({"path": context_path, "line": start, "reason": str(exc)})
                continue
            excerpt_lines, counted = [], 0
            for line in excerpt["lines"]:
                line_size = len(line["text"].encode()) + 1
                if used + counted + line_size > 32 * 1024:
                    break
                excerpt_lines.append(line)
                counted += line_size
            if len(excerpt_lines) != len(excerpt["lines"]):
                excerpt["truncated"] = True
                unresolved.append({"path": context_path, "line": excerpt_lines[-1]["number"] + 1 if excerpt_lines else start, "reason": "Context excerpt truncated; use read_source"})
            if excerpt_lines:
                excerpt["lines"] = excerpt_lines
                excerpt["end_line"] = excerpt_lines[-1]["number"]
                excerpt["reason"] = reason
                excerpts.append(excerpt)
                used += counted
        if owned["slice_count"] > 1:
            unresolved.append({"path": path, "line": owned["start_line"], "reason": "Unit is sliced; inspect adjacent slices and full parent where necessary"})
        if owned["parse_incomplete"]:
            unresolved.append({"path": path, "reason": "PHP syntax index contains parse errors; inspect original source"})
        return {"snapshot_id": snapshot_id, "unit_id": owned["id"], "excerpts": excerpts, "unresolved_dependencies": unresolved, "limitations": ["Static syntax context is not a complete call graph", "Dynamic dispatch and includes require manual source reads"]}

    # --- planner-oriented project context ---------------------------------

    def build_project_map(
        self,
        snapshot_id: str,
        allowed_paths: set[str] | None = None,
    ) -> dict:
        """Return a source-free, immutable project map for the Planner.

        The map deliberately contains paths, symbols and static relations instead of
        whole source files.  This lets a planner reason about a project as a system
        while the worker remains responsible for reading the exact source evidence.
        ``allowed_paths`` is the run's frozen scope and is applied to every relation
        so a planner cannot use an out-of-scope file as a hidden hint.
        """
        snapshot = self.get_snapshot(snapshot_id)
        # A snapshot now holds a whole project: every readable text file is in scope,
        # and only PHP files have a symbol index.  Binary entries are registered but
        # excluded from the map so the Planner cannot select something unreadable.
        text_files = {
            item["path"]: item
            for item in snapshot["files"]
            if item.get("kind", "text" if not item.get("excluded", False) else "binary") == "text"
        }
        binary_files = [
            {"path": item["path"], "size": int(item.get("size") or 0)}
            for item in snapshot["files"]
            if item.get("kind") == "binary"
        ]
        syntax = self.syntax_index(snapshot_id)
        scope = set(allowed_paths) if allowed_paths is not None else set(text_files)
        scope &= set(text_files)
        # Precomputed once: an O(files x units) scan inside the loop below is fine for
        # a demo snapshot and fatal for a whole project.
        top_level_paths = {
            unit.get("file_path")
            for unit in snapshot.get("units") or []
            if unit.get("kind") == "top_level"
        }
        file_rows = []
        directories: set[str] = set()
        symbols: list[dict] = []
        includes: list[dict] = []
        calls: list[dict] = []
        profiles: dict[str, dict] = {}
        available = set(text_files)

        for path in sorted(scope):
            record = text_files[path]
            index = syntax.get(path, {})
            parent = PurePosixPath(path).parent
            while str(parent) not in {"", "."}:
                directories.add(str(parent))
                parent = parent.parent
            profile = _project_path_profile(path)
            profiles[path] = profile
            file_rows.append({
                "path": path,
                "line_count": int(record.get("line_count") or 0),
                "size": int(record.get("size") or 0),
                "language": record.get("language") or "text",
                "is_php": bool(record.get("is_php")),
                "dependency_tree": bool(record.get("dependency_tree")),
                "parse_errors": list(record.get("parse_errors") or []),
                # Kept as a source-index fact for callers that use it, but never
                # interpreted as an execution or routing fact below.
                "has_top_level": path in top_level_paths,
                "roles": profile["roles"],
                "module": _project_module_path(path),
            })
            for item in index.get("classes", []):
                symbols.append({
                    "path": path,
                    "name": item.get("name") or "<anonymous class>",
                    "kind": "class",
                    "start_line": item.get("start_line"),
                    "end_line": item.get("end_line"),
                })
            for item in index.get("functions", []):
                symbols.append({
                    "path": path,
                    "name": item.get("symbol") or item.get("name") or "<anonymous>",
                    "short_name": item.get("name") or "<anonymous>",
                    "kind": "method" if item.get("class_name") else "function",
                    "class_name": item.get("class_name"),
                    "start_line": item.get("start_line"),
                    "end_line": item.get("end_line"),
                })
            for item in index.get("includes", []):
                resolved = self._resolve_include(str(item.get("expression") or ""), path, available)
                includes.append({
                    "from_path": path,
                    "to_path": resolved if resolved in scope else None,
                    "line": item.get("start_line"),
                    "expression": str(item.get("expression") or "")[:300],
                    "resolved_outside_scope": bool(resolved and resolved not in scope),
                })
            for item in index.get("calls", []):
                calls.append({
                    "path": path,
                    "name": item.get("name") or "<dynamic>",
                    "line": item.get("start_line"),
                })

        inbound_counts = {path: 0 for path in scope}
        outbound_counts = {path: 0 for path in scope}
        unresolved_include_count = 0
        for edge in includes:
            source = str(edge.get("from_path") or "")
            target = edge.get("to_path")
            if source in outbound_counts:
                outbound_counts[source] += 1
            if target in inbound_counts:
                inbound_counts[str(target)] += 1
            elif target is None:
                unresolved_include_count += 1

        entrypoints: list[dict] = []
        unresolved_root_candidates: list[dict] = []
        role_counts: dict[str, int] = {}
        for file_row in file_rows:
            path = file_row["path"]
            profile = profiles[path]
            file_row["static_inbound_includes"] = inbound_counts[path]
            file_row["static_outbound_includes"] = outbound_counts[path]
            for role in file_row["roles"]:
                role_counts[role] = role_counts.get(role, 0) + 1
            candidate = profile.get("entrypoint")
            if candidate:
                reason, priority = candidate
                entrypoints.append({
                    "path": path,
                    "reason": reason,
                    "confidence": "high",
                    "priority": priority,
                    "signals": list(profile.get("signals") or []),
                })
            # Static include coverage is incomplete in normal PHP applications.
            # Preserve no-inbound scripts as a low-confidence investigation lead, but
            # do not feed them to the Planner or worker as if they were routes.
            elif not profile.get("non_entry") and not inbound_counts[path] and file_row["has_top_level"]:
                unresolved_root_candidates.append({
                    "path": path,
                    "reason": "no_resolved_static_inbound_include",
                    "confidence": "low",
                    "signals": ["unresolved_include_graph"],
                })

        entrypoints.sort(key=lambda item: (-int(item["priority"]), item["path"]))
        unresolved_root_candidates.sort(key=lambda item: item["path"])
        module_data: dict[str, dict] = {}
        for row in file_rows:
            module = str(row["module"])
            current = module_data.setdefault(module, {
                "path": module,
                "file_count": 0,
                "role_counts": {},
                "entrypoints": [],
                "resolved_include_edges": 0,
                "unresolved_include_edges": 0,
                "call_counts": {},
            })
            current["file_count"] += 1
            for role in row["roles"]:
                current["role_counts"][role] = current["role_counts"].get(role, 0) + 1
        module_by_path = {row["path"]: str(row["module"]) for row in file_rows}
        for entry in entrypoints:
            module_data[module_by_path[entry["path"]]]["entrypoints"].append(entry["path"])
        cross_module_edges = 0
        for edge in includes:
            source_module = module_by_path.get(str(edge.get("from_path") or ""))
            target_module = module_by_path.get(str(edge.get("to_path") or ""))
            if source_module is None:
                continue
            if target_module is None:
                module_data[source_module]["unresolved_include_edges"] += 1
            else:
                module_data[source_module]["resolved_include_edges"] += 1
                if source_module != target_module:
                    cross_module_edges += 1
        for call in calls:
            module = module_by_path.get(str(call.get("path") or ""))
            name = str(call.get("name") or "<dynamic>")
            if module is not None and name != "<dynamic>":
                counts = module_data[module]["call_counts"]
                counts[name] = counts.get(name, 0) + 1
        modules = []
        for value in module_data.values():
            call_counts = value.pop("call_counts")
            modules.append({
                **value,
                "entrypoints": value["entrypoints"][:12],
                "notable_calls": [
                    {"name": name, "count": count}
                    for name, count in sorted(call_counts.items(), key=lambda item: (-item[1], item[0]))[:8]
                ],
            })
        modules.sort(key=lambda item: (-len(item["entrypoints"]), -int(item["file_count"]), item["path"]))
        bootstrap_files = [
            {"path": row["path"], "module": row["module"]}
            for row in file_rows if "bootstrap" in row["roles"]
        ]

        return {
            "snapshot_id": snapshot_id,
            "scope": sorted(scope),
            "files": file_rows,
            "directories": sorted(directories),
            "symbols": sorted(symbols, key=lambda item: (item["path"], int(item.get("start_line") or 0), item["name"])),
            "includes": includes,
            "calls": calls,
            "entrypoints": entrypoints,
            "unresolved_root_candidates": unresolved_root_candidates,
            "binary_files": binary_files[:MAX_LISTED_PATHS],
            "architecture": {
                "role_counts": dict(sorted(role_counts.items())),
                "modules": modules,
                "bootstrap_files": bootstrap_files,
                "include_graph": {
                    "resolved_edges": len(includes) - unresolved_include_count,
                    "unresolved_edges": unresolved_include_count,
                    "cross_module_edges": cross_module_edges,
                },
            },
            "parse_errors": [
                {"path": row["path"], "errors": row["parse_errors"]}
                for row in file_rows if row["parse_errors"]
            ],
            "stats": {
                "files": len(file_rows),
                "symbols": len(symbols),
                "includes": len(includes),
                "calls": len(calls),
                "entrypoints": len(entrypoints),
                "low_confidence_roots": len(unresolved_root_candidates),
                "unresolved_includes": unresolved_include_count,
                "modules": len(modules),
                "binary_files": len(binary_files),
                "php_files": sum(1 for row in file_rows if row["is_php"]),
                "dependency_tree_files": sum(1 for row in file_rows if row["dependency_tree"]),
            },
            "limitations": [
                "PHP files are indexed with a tree-sitter grammar; every other language is indexed as plain text lines. There is no cross-language symbol resolution.",
                "Static parsing does not resolve dynamic dispatch, reflection, framework routing, or runtime include paths.",
                "Entrypoints are high-confidence path candidates, not proof of runtime routing; unresolved static include roots are kept separately as low-confidence leads.",
                "Binary files are registered with their size only and cannot be read or searched.",
                "The map is an index for planning, not source evidence; workers must read cited lines before reporting a finding.",
            ],
        }

    def get_project_map(self, snapshot_id: str, allowed_paths: set[str] | None = None) -> dict:
        """Public alias used by the coordinator and API layer."""
        return self.build_project_map(snapshot_id, allowed_paths)

    def build_context_bundle(
        self,
        snapshot_id: str,
        task: dict,
        allowed_paths: set[str] | None = None,
        max_bytes: int = 64 * 1024,
    ) -> dict:
        """Prepare a bounded, multi-file source bundle for one planner task.

        The host selects only planner-validated paths and symbols.  The result is
        still fed into the worker ledger line-by-line, so visible source and eligible
        evidence always remain the same set.  This method never executes code or
        resolves a dynamic include.
        """
        if max_bytes < 1024:
            raise ValueError("context bundle budget is too small")
        project_map = self.build_project_map(snapshot_id, allowed_paths)
        scope = set(project_map["scope"])
        all_files = {item["path"]: item for item in project_map["files"]}
        symbols = project_map["symbols"]
        context = task.get("context_spec") if isinstance(task.get("context_spec"), dict) else task
        source_refs = context.get("source_refs") or []
        requested_symbols = {str(item).casefold() for item in context.get("target_symbols") or [] if str(item).strip()}
        requested_paths = [str(item) for item in context.get("scope_paths") or [] if str(item) in scope]
        query_hints = [str(item).strip()[:240] for item in context.get("query_hints") or [] if str(item).strip()]
        requests: list[tuple[str, int, int, str]] = []
        unresolved: list[dict] = []
        resolved_hints: list[dict] = []

        for ref in source_refs:
            if not isinstance(ref, dict):
                continue
            path = str(ref.get("path") or "")
            if path not in scope:
                unresolved.append({"path": path, "reason": "Planner selected a path outside the frozen scope"})
                continue
            limit = int(all_files[path].get("line_count") or 1)
            start = max(1, int(ref.get("start_line") or 1))
            end = min(limit, max(start, int(ref.get("end_line") or start)))
            requests.append((path, start, min(end, start + MAX_READ_LINES - 1), str(ref.get("reason") or "planner_source_ref")))

        if requested_symbols:
            for symbol in symbols:
                names = {str(symbol.get("name") or "").casefold(), str(symbol.get("short_name") or "").casefold()}
                if not names.intersection(requested_symbols):
                    continue
                path = str(symbol.get("path") or "")
                if path not in scope:
                    continue
                start = max(1, int(symbol.get("start_line") or 1))
                end = min(int(symbol.get("end_line") or start), start + MAX_READ_LINES - 1)
                requests.append((path, start, end, "planner_target_symbol"))

        for path in requested_paths:
            requests.append((path, 1, min(int(all_files[path].get("line_count") or 1), 160), "planner_selected_file"))

        # Query hints are navigation aids, not source claims.  Resolve them against
        # high-confidence entry candidates first, then named symbols and calls.  This
        # prevents a reconnaissance task from falling back to alphabetic files while
        # still letting a Planner ask for a target-specific cross-file starting set.
        for raw_hint in query_hints[:12]:
            hint = raw_hint.casefold()
            hint_matches = 0
            for entry in project_map.get("entrypoints") or []:
                path = str(entry.get("path") or "")
                if path in scope and hint in path.casefold():
                    requests.append((path, 1, min(int(all_files[path].get("line_count") or 1), 160), "planner_query_hint_entrypoint"))
                    hint_matches += 1
                    if hint_matches >= 4:
                        break
            if hint_matches < 4:
                for symbol in symbols:
                    path = str(symbol.get("path") or "")
                    names = " ".join(str(symbol.get(key) or "") for key in ("name", "short_name"))
                    if path not in scope or (hint not in path.casefold() and hint not in names.casefold()):
                        continue
                    start = max(1, int(symbol.get("start_line") or 1))
                    end = min(int(symbol.get("end_line") or start), start + MAX_READ_LINES - 1)
                    requests.append((path, start, end, "planner_query_hint_symbol"))
                    hint_matches += 1
                    if hint_matches >= 8:
                        break
            if hint_matches < 8:
                for call in project_map.get("calls") or []:
                    path = str(call.get("path") or "")
                    name = str(call.get("name") or "")
                    if path not in scope or (hint not in path.casefold() and hint not in name.casefold()):
                        continue
                    start = max(1, int(call.get("line") or 1) - 8)
                    requests.append((path, start, min(int(all_files[path].get("line_count") or start), start + 120), "planner_query_hint_call"))
                    hint_matches += 1
                    if hint_matches >= 12:
                        break
            resolved_hints.append({"hint": raw_hint, "matches": hint_matches})

        # A planner can intentionally leave source refs empty for reconnaissance.
        # Seed it from ranked high-confidence entries and bootstraps, never from a
        # parser top-level unit, an unresolved root, or alphabetically first symbols.
        if not requests:
            for entry in project_map["entrypoints"][:4]:
                path = entry["path"]
                requests.append((path, 1, min(int(all_files[path].get("line_count") or 1), 120), "project_entrypoint"))
            for bootstrap in (project_map.get("architecture") or {}).get("bootstrap_files") or []:
                path = str(bootstrap.get("path") or "")
                if path in scope:
                    requests.append((path, 1, min(int(all_files[path].get("line_count") or 1), 120), "project_bootstrap"))
                if len(requests) >= 6:
                    break
            if not requests:
                for candidate in project_map.get("unresolved_root_candidates") or []:
                    path = str(candidate.get("path") or "")
                    if path in scope:
                        requests.append((path, 1, min(int(all_files[path].get("line_count") or 1), 120), "low_confidence_orientation_lead"))
                    if len(requests) >= 2:
                        break
                if requests:
                    unresolved.append({
                        "reason": "No high-confidence entry candidate was available; orientation uses low-confidence static roots only.",
                    })
            if not requests:
                # A pure non-PHP project has no entrypoint, no bootstrap file and no
                # ``top_level`` unit, so both seeds above are empty.  Without this
                # fallback every worker task would be blocked for missing context and
                # the whole audit loop would never start.
                for path in _orientation_leads(project_map, scope)[:4]:
                    requests.append((path, 1, min(int(all_files[path].get("line_count") or 1), 120), "generic_orientation_lead"))
                if requests:
                    unresolved.append({
                        "reason": "The snapshot has no PHP entry or bootstrap candidate; orientation uses deterministic generic leads (manifests, configuration, application code, web roots).",
                    })

        # For every selected path, put its static include targets and callers in the
        # candidate set. This creates genuinely multi-file context without pretending
        # the static graph is complete.
        selected_paths = {path for path, _, _, _ in requests}
        for edge in project_map["includes"]:
            if edge.get("from_path") in selected_paths and edge.get("to_path") in scope:
                target = str(edge["to_path"])
                requests.append((target, 1, min(int(all_files[target].get("line_count") or 1), 120), "static_include"))
            if edge.get("to_path") in selected_paths and edge.get("from_path") in scope:
                source = str(edge["from_path"])
                requests.append((source, 1, min(int(all_files[source].get("line_count") or 1), 120), "static_includer"))
            if edge.get("resolved_outside_scope"):
                unresolved.append({"path": edge.get("from_path"), "line": edge.get("line"), "reason": "Static include resolves outside the frozen scope"})

        excerpts: list[dict] = []
        used = 0
        seen: set[tuple[str, int, int]] = set()
        for path, start, end, reason in requests:
            key = (path, start, end)
            if key in seen or path not in scope or len(excerpts) >= 16 or used >= max_bytes:
                continue
            seen.add(key)
            try:
                value = self.read_source(snapshot_id, path, start, end)
            except ValueError as exc:
                unresolved.append({"path": path, "line": start, "reason": str(exc)})
                continue
            kept: list[dict] = []
            for line in value.get("lines") or []:
                size = len(f"{path}:{line['number']} | {line['text']}\n".encode("utf-8"))
                if used + size > max_bytes:
                    break
                kept.append(line)
                used += size
            if not kept:
                unresolved.append({"path": path, "line": start, "reason": "Context bundle byte budget reached"})
                break
            excerpts.append({
                "path": path,
                "start_line": kept[0]["number"],
                "end_line": kept[-1]["number"],
                "lines": kept,
                "reason": reason,
                "truncated": len(kept) != len(value.get("lines") or []),
            })
            if len(kept) != len(value.get("lines") or []):
                unresolved.append({"path": path, "line": kept[-1]["number"] + 1, "reason": "Context bundle excerpt was truncated"})

        relation_summary = {
            "selected_paths": sorted({item["path"] for item in excerpts}),
            "selected_symbols": sorted(requested_symbols),
            "query_hints": resolved_hints,
            "included_excerpts": len(excerpts),
            "map_stats": project_map["stats"],
        }
        unique_unresolved: list[dict] = []
        unresolved_seen: set[str] = set()
        for item in unresolved:
            key = json.dumps(item, ensure_ascii=False, sort_keys=True)
            if key not in unresolved_seen:
                unresolved_seen.add(key)
                unique_unresolved.append(item)
        return {
            "snapshot_id": snapshot_id,
            "scope": sorted(scope),
            "excerpts": excerpts,
            "unresolved_dependencies": unique_unresolved,
            "relation_summary": relation_summary,
            "limitations": project_map["limitations"],
        }
