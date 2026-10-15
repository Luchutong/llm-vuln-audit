import hashlib
import io
from pathlib import Path
import stat
import zipfile

import pytest

from audit import source
from audit.source import SourceRepository


def make_zip(files, *, compression=zipfile.ZIP_DEFLATED):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=compression) as archive:
        for path, content in files:
            archive.writestr(path, content)
    return target.getvalue()


@pytest.fixture
def repository(tmp_path):
    return SourceRepository(tmp_path)


@pytest.mark.parametrize("path", ["../escape.php", "/absolute.php", "a/../../x.php", "C:/x.php", "a\\..\\x.php", "./x.php", "a//x.php"])
def test_import_rejects_unsafe_paths_atomically(repository, path):
    with pytest.raises(ValueError):
        repository.import_zip(make_zip([("good.php", "<?php echo 1;"), (path, "<?php echo 2;")]), "project.zip")
    assert list(repository.snapshots.iterdir()) == []


@pytest.mark.parametrize("files", [
    [("a.php", "one"), ("A.php", "two")],
    [("src", "file"), ("src/a.php", "other")],
    [("caf\u00e9.php", "one"), ("cafe\u0301.php", "two")],
    [("dup.php", "one"), ("dup.php", "two")],
])
def test_import_rejects_path_collisions(repository, files):
    with pytest.raises(ValueError, match="collision|colliding"):
        repository.import_zip(make_zip(files), "project.zip")


def test_import_rejects_symlinks_and_bombs(repository, monkeypatch):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo("link.php")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../secret")
    with pytest.raises(ValueError, match="symbolic"):
        repository.import_zip(stream.getvalue(), "link.zip")
    monkeypatch.setattr(source, "MAX_COMPRESSION_RATIO", 3)
    with pytest.raises(ValueError, match="compression ratio"):
        repository.import_zip(make_zip([("bomb.php", "a" * 100_000)]), "bomb.zip")
    monkeypatch.setattr(source, "MAX_COMPRESSION_RATIO", 1000)
    monkeypatch.setattr(source, "MAX_EXTRACTED_BYTES", 9)
    with pytest.raises(ValueError, match="extraction limit"):
        repository.import_zip(make_zip([("a.php", "12345"), ("b.php", "12345")]), "large.zip")


def test_immutable_snapshot_keeps_original_hashes_and_context(repository):
    original = b"<?php\r\n// birthday comment\r\n\r\n// Validate untrusted input before output\r\necho $_GET['name'];\r\n"
    archive = make_zip([("app.php", original), ("vendor/helper.inc", "<?php function help(){ return 'ok'; }"), ("assets/page.html", "<h1>page</h1>")])
    snapshot = repository.import_zip(archive, "project.zip")
    loaded = SourceRepository(repository.storage).get_snapshot(snapshot["id"])
    assert loaded == snapshot
    assert snapshot["archive_sha256"] == hashlib.sha256(archive).hexdigest()
    stored = repository.snapshots / snapshot["id"]
    assert (stored / "sources/app.php").read_bytes() == original
    assert (stored / "archive.zip").read_bytes() == archive
    assert (stored / "sources/app.php").stat().st_mode & 0o222 == 0
    php = next(file for file in snapshot["files"] if file["path"] == "app.php")
    assert php["sha256"] == hashlib.sha256(original).hexdigest()
    assert php["line_count"] == 5
    assert "vendor/helper.inc" in snapshot["excluded_files"]
    assert any(unit["file_path"] == "vendor/helper.inc" for unit in snapshot["units"])
    # Default scope excludes dependencies, while read-only context is available.
    assert repository.read_source(snapshot["id"], "vendor/helper.inc")["lines"]
    unit = next(unit for unit in snapshot["units"] if unit["file_path"] == "app.php")
    numbers = {line["number"] for line in unit["cleaned_lines"]}
    assert 2 not in numbers and 3 not in numbers
    assert 4 in numbers and 5 in numbers
    assert any(item["reason"] == "irrelevant_comment" for item in unit["omissions"])
    assert repository.read_source(snapshot["id"], "app.php", 2, 4)["lines"] == [{"number": 2, "text": "// birthday comment"}, {"number": 3, "text": ""}, {"number": 4, "text": "// Validate untrusted input before output"}]


def test_all_symbols_without_sink_are_indexed_nested_closure_owned(repository):
    code = """<?php
echo 'before';
class Example {
    private $name = 'default';
    function first() {
        $closure = function ($v) { return $v + 1; };
        function nested() { return 2; }
        return $closure(3);
    }
}
function quiet() { return 7; }
echo 'after';
"""
    snapshot = repository.import_zip(make_zip([("one.php", code)]), "one.zip")
    units = snapshot["units"]
    symbols = {unit["symbol"] for unit in units}
    assert {"Example::first", "nested", "quiet", "<top-level>"}.issubset(symbols)
    assert not any(unit["symbol"] == "<anonymous>" for unit in units)
    quiet = next(unit for unit in units if unit["symbol"] == "quiet")
    assert quiet["priority"] == 0
    assert quiet["start_line"] == quiet["end_line"] == 11
    assert quiet["checklist"] == ["sqli", "xss_r", "command_injection"]
    first = next(unit for unit in units if unit["symbol"] == "Example::first")
    assert (first["start_line"], first["end_line"]) == (5, 9)
    assert "function ($v)" in "\n".join(line["text"] for line in first["cleaned_lines"])
    # Stable IDs depend on archive and source coordinates, not import UUID.
    repeat = repository.import_zip(make_zip([("one.php", code)]), "one.zip")
    assert [unit["id"] for unit in units] == [unit["id"] for unit in repeat["units"]]


def test_top_level_and_functions_sharing_line_have_exact_byte_ranges(repository):
    code = b"<?php echo 'a'; function clean() { return 1; } echo 'b';"
    snapshot = repository.import_zip(make_zip([("single.php", code)]), "single.zip")
    fn = next(unit for unit in snapshot["units"] if unit["kind"] == "function")
    assert code[fn["start_byte"]:fn["end_byte"]] == b"function clean() { return 1; }"
    top = sorted((unit for unit in snapshot["units"] if unit["kind"] == "top_level"), key=lambda unit: unit["start_byte"])
    assert len(top) == 2
    assert top[0]["end_byte"] == fn["start_byte"]
    assert top[1]["start_byte"] == fn["end_byte"]
    assert top[1]["cleaned_lines"][0]["start_column"] > 0


def test_cleaning_preserves_template_and_multiline_strings(repository):
    code = """<?php
$value = <<<'TEXT'
// this is literal content

/* this too */
TEXT;
// unrelated birthday note
?>
<script>
// preserve browser script as template content

console.log('hello');
</script>
"""
    snapshot = repository.import_zip(make_zip([("template.phtml", code)]), "template.zip")
    shown = {line["number"]: line["text"] for unit in snapshot["units"] for line in unit["cleaned_lines"]}
    assert shown[3] == "// this is literal content"
    assert shown[4] == "" and shown[5] == "/* this too */"
    assert 7 not in shown
    assert shown[10] == "// preserve browser script as template content"
    assert shown[11] == ""


def test_statement_slices_limits_overlap_and_original_line_coverage(repository):
    code = "<?php\nfunction long_function() {\n" + "".join(f"  $a = {number};\n" for number in range(600)) + "}\n"
    snapshot = repository.import_zip(make_zip([("long.php", code)]), "long.zip")
    units = sorted((unit for unit in snapshot["units"] if unit["symbol"] == "long_function"), key=lambda unit: unit["slice_index"])
    assert len(units) >= 4
    coverage = set()
    for unit in units:
        assert unit["end_line"] - unit["start_line"] + 1 <= 200
        assert unit["end_byte"] - unit["start_byte"] <= 16 * 1024
        coverage.update(line["number"] for line in unit["cleaned_lines"])
        assert unit["slice_count"] == len(units)
    assert coverage == set(range(2, 604))
    assert all(unit["slice_rule"]["overlap_lines"] == 24 for unit in units[:-1])
    assert all(unit["slice_rule"]["boundary"] == "statement_boundary" for unit in units[:-1])


def test_oversized_statement_preserved_in_bounded_slices(repository):
    code = "<?php\n$value = '" + "x" * 50_000 + "';\necho $value;"
    snapshot = repository.import_zip(make_zip([("big.php", code)]), "big.zip")
    assert any(unit["slice_rule"]["boundary"] == "forced_byte_boundary" for unit in snapshot["units"])
    assert all(unit["end_byte"] - unit["start_byte"] <= 16384 for unit in snapshot["units"])
    covered = set()
    for unit in snapshot["units"]:
        covered.update(range(unit["start_byte"], unit["end_byte"]))
    assert covered == set(range(len(code.encode())))


@pytest.mark.parametrize("code", ["<?php function nope( { echo $_GET['x'];", "<?php echo 1"])
def test_parse_failure_is_flagged_and_still_indexed(repository, code):
    snapshot = repository.import_zip(make_zip([("broken.php", code)]), "broken.zip")
    assert snapshot["files"][0]["parse_errors"]
    assert snapshot["units"] and snapshot["units"][0]["parse_incomplete"]
    assert snapshot["warnings"]


def test_context_cross_file_includes_methods_callers_and_missing_dependencies(repository):
    snapshot = repository.import_zip(make_zip([
        ("src/index.php", "<?php require __DIR__ . '/unit.php'; run($_GET['q']);"),
        ("src/unit.php", "<?php\ninclude __DIR__ . '/../vendor/helper.inc';\ninclude $dynamic;\nclass Service {\n public function do_it($x) { return help($x); }\n}\nfunction run($x) { return help($x); }\n"),
        ("vendor/helper.inc", "<?php\nfunction help($x) { return htmlspecialchars($x); }\n"),
    ]), "context.zip")
    unit = next(unit for unit in snapshot["units"] if unit["symbol"] == "Service::do_it")
    context = repository.get_context(snapshot["id"], unit)
    assert any(item["reason"] == "owning_class" for item in context["excerpts"])
    assert any(item["path"] == "vendor/helper.inc" for item in context["excerpts"])
    assert any(item["path"] == "src/index.php" for item in context["excerpts"])
    assert any("$dynamic" in item.get("expression", "") for item in context["unresolved_dependencies"])
    run = next(unit for unit in snapshot["units"] if unit["symbol"] == "run")
    assert any(item["reason"] == "call_location" for item in repository.get_context(snapshot["id"], run)["excerpts"])
    with pytest.raises(ValueError, match="belong"):
        repository.get_context(snapshot["id"], {"id": "forged"})


def test_import_indexes_php_tags_without_a_standard_suffix(repository):
    """Framework modules and extensionless PHP entrypoints are real project code.

    The target workflow accepts arbitrary PHP project ZIPs, so suffix matching alone
    must not silently drop a Drupal-style module or a command entrypoint that carries a
    PHP opening tag.
    """
    snapshot = repository.import_zip(make_zip([
        ("modules/access.module", "<?php\nfunction check_access() { return true; }\n"),
        ("bin/worker", "#!/usr/bin/env php\n<?php\necho 'ok';\n"),
        ("legacy/handler.php6", "<?php\nfunction legacy_handler() { return true; }\n"),
        ("modules/short-tag.module", "<? echo 'short tag';\n"),
        ("docs/notes.txt", "not PHP source"),
    ]), "mixed.zip")
    files = {item["path"]: item for item in snapshot["files"]}
    assert files["modules/access.module"]["is_php"] is True
    assert files["modules/access.module"]["excluded"] is False
    assert files["bin/worker"]["is_php"] is True
    assert files["bin/worker"]["excluded"] is False
    assert files["legacy/handler.php6"]["is_php"] is True
    assert files["legacy/handler.php6"]["excluded"] is False
    assert files["modules/short-tag.module"]["is_php"] is True
    assert files["modules/short-tag.module"]["excluded"] is False
    assert files["docs/notes.txt"]["is_php"] is False
    assert files["docs/notes.txt"]["excluded"] is True
    assert {unit["file_path"] for unit in snapshot["units"]} >= {
        "modules/access.module", "bin/worker", "legacy/handler.php6",
        "modules/short-tag.module",
    }


def test_import_detects_a_late_php_tag_in_framework_or_extensionless_source(repository):
    """A PHP block can follow a large template/banner in a nonstandard filename."""
    prefix = b" " * 8_193
    snapshot = repository.import_zip(make_zip([
        ("modules/late.module", prefix + b"<?php\nfunction late_module() { return true; }\n"),
        ("bin/late-worker", prefix + b"<?= 'worker';\n"),
    ]), "late-tag.zip")
    files = {item["path"]: item for item in snapshot["files"]}
    assert files["modules/late.module"]["is_php"] is True
    assert files["modules/late.module"]["excluded"] is False
    assert files["bin/late-worker"]["is_php"] is True
    assert files["bin/late-worker"]["excluded"] is False
    assert {unit["file_path"] for unit in snapshot["units"]} >= {
        "modules/late.module", "bin/late-worker",
    }


def test_dvwa_project_map_limits_entries_to_high_confidence_request_paths(repository):
    """A real PHP application must not turn every executable file into an entry."""
    archive = Path(__file__).resolve().parents[2] / "demo" / "dvwa-source.zip"
    snapshot = repository.import_zip(archive.read_bytes(), archive.name)

    project_map = repository.build_project_map(snapshot["id"])
    entrypoints = project_map["entrypoints"]

    assert project_map["stats"]["files"] > 100
    assert entrypoints
    assert len(entrypoints) < project_map["stats"]["files"]
    assert all(item["confidence"] == "high" for item in entrypoints)
    assert all(
        marker not in item["path"]
        for item in entrypoints
        for marker in ("/source/", "/help/", "/includes/")
    )
    assert project_map["architecture"]["modules"]
    assert project_map["architecture"]["role_counts"]


def test_default_project_map_omits_excluded_dependency_tree_but_explicit_scope_keeps_it(repository):
    snapshot = repository.import_zip(make_zip([
        ("public/index.php", "<?php echo 'ok';"),
        ("vendor/package/helper.php", "<?php function helper() { return true; }"),
    ]), "scope-map.zip")

    default_map = repository.build_project_map(snapshot["id"])
    explicit_map = repository.build_project_map(snapshot["id"], {"vendor/package/helper.php"})

    assert default_map["scope"] == ["public/index.php"]
    assert explicit_map["scope"] == ["vendor/package/helper.php"]


def test_context_and_search_respect_a_task_frozen_scope(repository):
    """Task tools cannot silently escape the source files frozen into the run."""
    snapshot = repository.import_zip(make_zip([
        ("src/index.php", "<?php require __DIR__ . '/unit.php'; run($_GET['q']);"),
        ("src/unit.php", "<?php\ninclude __DIR__ . '/../vendor/helper.inc';\nclass Service {\n public function do_it($x) { return help($x); }\n}\nfunction run($x) { return help($x); }\n"),
        ("vendor/helper.inc", "<?php\nfunction help($x) { return htmlspecialchars($x); }\n"),
    ]), "scoped.zip")
    unit = next(item for item in snapshot["units"] if item["symbol"] == "Service::do_it")
    allowed = {"src/unit.php"}

    context = repository.get_context(snapshot["id"], unit, allowed_paths=allowed)
    assert context["excerpts"]
    assert {item["path"] for item in context["excerpts"]} == allowed
    assert any(
        item["reason"] == "Related source is outside this task's frozen scope"
        for item in context["unresolved_dependencies"]
    )

    matches = repository.search_code(snapshot["id"], "help", allowed_paths=allowed)["matches"]
    assert matches and {item["path"] for item in matches} == allowed
    with pytest.raises(ValueError, match="frozen scope"):
        repository.search_code(snapshot["id"], "help", path="vendor/helper.inc", allowed_paths=allowed)


def test_literal_search_range_limits_and_integrity(repository):
    snapshot = repository.import_zip(make_zip([("app.php", "<?php\n// literal [a-z].*\necho $_GET['a'];\necho $_GET['b'];\n")]), "search.zip")
    matches = repository.search_code(snapshot["id"], "[a-z].*")["matches"]
    assert len(matches) == 1 and matches[0]["line"] == 2
    assert repository.search_code(snapshot["id"], "GET", limit=1)["truncated"]
    for start, end in [(0, 1), (4, 3), (1, 401), (99, 100)]:
        with pytest.raises(ValueError):
            repository.read_source(snapshot["id"], "app.php", start, end)
    with pytest.raises(ValueError):
        repository.search_code(snapshot["id"], "x\ny")
    with pytest.raises(ValueError):
        repository.read_source(snapshot["id"], "../app.php")
    path = repository.snapshots / snapshot["id"] / "sources/app.php"
    path.chmod(0o644)
    path.write_text("tampered")
    with pytest.raises(ValueError, match="integrity"):
        repository.read_source(snapshot["id"], "app.php")
