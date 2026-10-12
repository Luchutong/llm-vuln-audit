"""Immutable ZIP snapshots and bounded, read-only PHP source tools.

Tree-sitter is a syntax index, never a vulnerability filter. Every named function,
method and remaining script region is indexed, including code without sink hits.
Original files are kept byte-for-byte; cleaning only changes model projections.
"""
from __future__ import annotations

import bisect
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


MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_EXTRACTED_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ENTRIES = 10_000
MAX_COMPRESSION_RATIO = 1000
MAX_SLICE_LINES = 200
MAX_SLICE_BYTES = 16 * 1024
SLICE_OVERLAP_LINES = 24
MAX_READ_LINES = 400
MAX_READ_BYTES = 64 * 1024
PHP_EXTENSIONS = {".php", ".inc", ".phtml"}
EXCLUDED_DIRECTORIES = {"vendor", "node_modules", "bower_components", "cache", "caches", "dist", "build", "coverage", "generated", ".git", ".hg", ".svn"}
SECURITY_COMMENT = re.compile(r"security|saniti|escap|validat|auth|csrf|inject|xss|sql|command|taint|input|password|whitelist|blacklist|用户|安全|漏洞|过滤|转义|验证|权限|密码", re.I)
PRIORITY_HINT = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|\b(?:mysqli_query|mysql_query|query|exec|system|shell_exec|passthru|echo|print)\b", re.I)
FUNCTION_TYPES = {"function_definition", "method_declaration"}
CLASS_TYPES = {"class_declaration", "interface_declaration", "trait_declaration", "enum_declaration", "anonymous_class"}
STRING_TYPES = {"string", "encapsed_string", "heredoc", "nowdoc", "text"}
INCLUDE_TYPES = {"include_expression", "include_once_expression", "require_expression", "require_once_expression"}
CALL_TYPES = {"function_call_expression", "member_call_expression", "scoped_call_expression", "nullsafe_member_call_expression"}


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


class SourceRepository:
    def __init__(self, storage: Path):
        self.storage = Path(storage)
        self.snapshots = self.storage / "snapshots"
        self.snapshots.mkdir(parents=True, exist_ok=True)
        self.parser = Parser(Language(tree_sitter_php.language_php()))
        self._parser_lock = threading.Lock()

    def _directory(self, snapshot_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", snapshot_id or ""):
            raise FileNotFoundError("Snapshot does not exist")
        directory = self.snapshots / snapshot_id
        if not (directory / "index.json").is_file():
            raise FileNotFoundError("Snapshot does not exist")
        return directory

    def get_snapshot(self, snapshot_id: str) -> dict:
        return json.loads((self._directory(snapshot_id) / "index.json").read_text("utf-8"))

    def import_zip(self, data: bytes, filename: str) -> dict:
        if not isinstance(data, bytes) or len(data) > MAX_ARCHIVE_BYTES:
            raise ValueError("ZIP exceeds the 32 MiB upload limit")
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except (zipfile.BadZipFile, OSError) as exc:
            raise ValueError("Invalid ZIP archive") from exc
        staging = Path(tempfile.mkdtemp(prefix=".import-", dir=self.snapshots))
        try:
            with archive:
                entries = archive.infolist()
                if len(entries) > MAX_ENTRIES:
                    raise ValueError("ZIP contains too many entries")
                checked = []
                normalized = {}
                total = 0
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
                    if entry.file_size > MAX_FILE_BYTES:
                        raise ValueError(f"ZIP entry exceeds the 8 MiB file limit: {name}")
                    if entry.file_size / max(1, entry.compress_size) > MAX_COMPRESSION_RATIO:
                        raise ValueError(f"ZIP compression ratio exceeds limit: {name}")
                    total += entry.file_size
                    if total > MAX_EXTRACTED_BYTES:
                        raise ValueError("ZIP exceeds the 128 MiB extraction limit")
                    checked.append((entry, name, key))
                for _, name, key in checked:
                    for parent in PurePosixPath(key).parents:
                        if str(parent) != "." and normalized.get(str(parent)) is False:
                            raise ValueError(f"ZIP file/directory collision: {name}")
                snapshot_id = uuid.uuid4().hex
                digest = _sha(data)
                sources = staging / "sources"
                sources.mkdir()
                files, units, syntax, warnings = [], [], {}, []
                extracted = 0
                for entry, name, _ in checked:
                    if entry.is_dir():
                        continue
                    with archive.open(entry) as handle:
                        content = handle.read(MAX_FILE_BYTES + 1)
                    extracted += len(content)
                    if len(content) != entry.file_size or len(content) > MAX_FILE_BYTES or extracted > MAX_EXTRACTED_BYTES:
                        raise ValueError("ZIP decompressed size does not match allowed bounds")
                    destination = sources / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                    reason = next((part for part in PurePosixPath(name).parts[:-1] if part.casefold() in EXCLUDED_DIRECTORIES), None)
                    is_php = PurePosixPath(name).suffix.casefold() in PHP_EXTENSIONS
                    record = {"path": name, "sha256": _sha(content), "size": len(content), "line_count": len(_lines(content)), "excluded": bool(reason) or not is_php, "exclude_reason": f"Default dependency/generated directory: {reason}" if reason else (None if is_php else "Not a PHP source file"), "is_php": is_php, "parse_errors": []}
                    try:
                        content.decode("utf-8")
                    except UnicodeDecodeError:
                        record["encoding_warning"] = "Not valid UTF-8; display uses replacement characters; original bytes preserved"
                        warnings.append(f"{name}: display decoding contains replacement characters")
                    if is_php:
                        file_units, file_syntax, errors = self._index(content, name, digest, snapshot_id)
                        record["parse_errors"] = errors
                        syntax[name] = file_syntax
                        units.extend(file_units)
                        if errors:
                            warnings.append(f"{name}: PHP parse errors; indexed units require context review")
                    files.append(record)
                snapshot = {"id": snapshot_id, "name": PurePosixPath(str(filename).replace("\\", "/")).name[:200], "created_at": datetime.now(timezone.utc).isoformat(), "archive_sha256": digest, "source": "uploaded_zip", "files": sorted(files, key=lambda item: item["path"]), "units": sorted(units, key=lambda item: (-item["priority"], item["file_path"], item["start_byte"])), "warnings": warnings, "immutable": True, "import_limits": {"archive_bytes": MAX_ARCHIVE_BYTES, "extracted_bytes": MAX_EXTRACTED_BYTES, "file_bytes": MAX_FILE_BYTES, "entries": MAX_ENTRIES, "compression_ratio": MAX_COMPRESSION_RATIO}, "excluded_files": [item["path"] for item in files if item["excluded"]]}
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
        snapshot = self.get_snapshot(snapshot_id)
        record = next((item for item in snapshot["files"] if item["path"] == path), None)
        if record is None:
            raise FileNotFoundError("Source file does not exist in snapshot")
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

    def search_code(self, snapshot_id: str, query: str, path: str | None = None, limit: int = 40) -> dict:
        if not isinstance(query, str) or not query or len(query) > 200 or "\n" in query or "\r" in query:
            raise ValueError("Search query must be a nonempty literal of at most 200 characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("Search limit must be between 1 and 100")
        snapshot = self.get_snapshot(snapshot_id)
        if path is not None:
            path = _path(path)
            if not any(item["path"] == path for item in snapshot["files"]):
                raise FileNotFoundError("Source file does not exist in snapshot")
        matches, size, truncated = [], 0, False
        directory = self._directory(snapshot_id) / "sources"
        for file in snapshot["files"]:
            if path is not None and file["path"] != path:
                continue
            if path is None and not file["is_php"]:
                continue
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
        return {"snapshot_id": snapshot_id, "query": query, "matches": matches, "truncated": truncated}

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

    def get_context(self, snapshot_id: str, unit: dict) -> dict:
        snapshot = self.get_snapshot(snapshot_id)
        owned = next((item for item in snapshot["units"] if item["id"] == unit.get("id")), None)
        if owned is None:
            raise ValueError("Audit unit does not belong to snapshot")
        syntax = json.loads((self._directory(snapshot_id) / "syntax.json").read_text("utf-8"))
        path = owned["file_path"]
        current = syntax[path]
        available = {item["path"] for item in snapshot["files"]}
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
            if len(excerpts) >= 12 or used >= 32 * 1024:
                unresolved.append({"path": context_path, "line": start, "reason": "Context tool output budget reached; use read_source"})
                continue
            try:
                excerpt = self.read_source(snapshot_id, context_path, start, end)
            except ValueError as exc:
                unresolved.append({"path": context_path, "line": start, "reason": str(exc)})
                continue
            allowed, counted = [], 0
            for line in excerpt["lines"]:
                line_size = len(line["text"].encode()) + 1
                if used + counted + line_size > 32 * 1024:
                    break
                allowed.append(line)
                counted += line_size
            if len(allowed) != len(excerpt["lines"]):
                excerpt["truncated"] = True
                unresolved.append({"path": context_path, "line": allowed[-1]["number"] + 1 if allowed else start, "reason": "Context excerpt truncated; use read_source"})
            if allowed:
                excerpt["lines"] = allowed
                excerpt["end_line"] = allowed[-1]["number"]
                excerpt["reason"] = reason
                excerpts.append(excerpt)
                used += counted
        if owned["slice_count"] > 1:
            unresolved.append({"path": path, "line": owned["start_line"], "reason": "Unit is sliced; inspect adjacent slices and full parent where necessary"})
        if owned["parse_incomplete"]:
            unresolved.append({"path": path, "reason": "PHP syntax index contains parse errors; inspect original source"})
        return {"snapshot_id": snapshot_id, "unit_id": owned["id"], "excerpts": excerpts, "unresolved_dependencies": unresolved, "limitations": ["Static syntax context is not a complete call graph", "Dynamic dispatch and includes require manual source reads"]}
