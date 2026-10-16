import hashlib
import io
import stat
import time
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


def test_import_rejects_symlinks_and_special_entries(repository):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo("link.php")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "../../secret")
    with pytest.raises(ValueError, match="symbolic"):
        repository.import_zip(stream.getvalue(), "link.zip")


def test_capacity_limits_skip_one_entry_instead_of_rejecting_the_project(repository, monkeypatch):
    """A whole project is the upload unit: one bad entry must not fail the import."""
    monkeypatch.setattr(source, "MAX_COMPRESSION_RATIO", 3)
    snapshot = repository.import_zip(make_zip([("bomb.php", "a" * 100_000), ("ok.php", "<?php echo 1;")]), "bomb.zip")
    assert [(item["path"], item["reason"]) for item in snapshot["skipped_files"]] == [("bomb.php", "compression_ratio")]
    assert [item["path"] for item in snapshot["files"]] == ["ok.php"]
    assert snapshot["stats"]["skipped_count"] == 1
    assert any("skipped at import" in warning for warning in snapshot["warnings"])

    monkeypatch.setattr(source, "MAX_FILE_BYTES", 6)
    snapshot = repository.import_zip(make_zip([("big.php", "<?php echo 1;"), ("small.php", "<?php")]), "big.zip")
    assert [(item["path"], item["reason"]) for item in snapshot["skipped_files"]] == [("big.php", "file_too_large")]
    assert [item["path"] for item in snapshot["files"]] == ["small.php"]

    monkeypatch.setattr(source, "MAX_ENTRIES", 1)
    snapshot = repository.import_zip(make_zip([("a.php", "<?php"), ("b.php", "<?php")]), "many.zip")
    # Budgets are applied in path order, so which entries a ZIP loses is reproducible.
    assert [(item["path"], item["reason"]) for item in snapshot["skipped_files"]] == [("b.php", "entry_limit")]


def test_cumulative_extraction_limit_still_rejects_the_whole_archive(repository, monkeypatch):
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


def test_php_tag_sniffing_stops_at_a_known_other_language(repository):
    """A Python or Markdown file that quotes PHP is not a PHP file.

    Whole-snapshot uploads make this load-bearing: ``db.py`` embeds PHP samples in its
    prompts, and treating it as PHP indexed hundreds of bogus units and reported
    tree-sitter ERROR nodes on it as its own parse errors.
    """
    snapshot = repository.import_zip(make_zip([
        ("backend/audit/agent.py", "PROMPT = '''<?php echo 1;'''\n\ndef run():\n    return PROMPT\n"),
        ("docs/design.md", "# 设计\n\n示例：\n\n```php\n<?php echo 'hi';\n```\n"),
        ("config/routes.json", '{"sample": "<?php echo 1;"}\n'),
        ("deploy/Dockerfile", "FROM php:8\n"),
        # Still sniffed: the suffix tables say nothing about these names.
        ("modules/access.module", "<?php\nfunction check_access() { return true; }\n"),
        ("bin/worker", "#!/usr/bin/env php\n<?php\necho 'ok';\n"),
    ]), "sniff.zip")
    files = {item["path"]: item for item in snapshot["files"]}

    for path in ("backend/audit/agent.py", "docs/design.md", "config/routes.json", "deploy/Dockerfile"):
        assert files[path]["is_php"] is False, path
        assert files[path]["parse_errors"] == [], path
    assert {unit["file_path"] for unit in snapshot["units"]} == {"modules/access.module", "bin/worker"}
    assert snapshot["stats"]["php_files"] == 2
    # The quoted text is still readable and searchable -- only the PHP interpretation
    # is refused.
    assert files["backend/audit/agent.py"]["kind"] == "text"
    assert repository.read_source(snapshot["id"], "backend/audit/agent.py", 1, 1)["lines"]


def php_web_app_files() -> list[tuple[str, str]]:
    """A PHP web application shaped like the ones this classifier was tuned against.

    Built here rather than read from a checked-in archive: the map's job is to limit
    orientation to high-confidence request paths, and a fixture that has to exist on disk
    -- and be fetched or regenerated before the suite can run -- is a suite that fails for
    a reason unrelated to the classifier.  What matters is the shape: a root front
    controller and root scripts, a web root, one index per feature module, and the three
    kinds of file that must never be offered as an entry -- the per-feature ``source/``
    and ``help/`` files, and the shared ``includes/`` and ``vendor/`` trees.
    """
    files = [
        ("index.php", "<?php\nrequire_once 'includes/page.inc.php';\nrender_page();\n"),
        ("login.php", "<?php\nrequire_once 'includes/page.inc.php';\nlogin();\n"),
        ("logout.php", "<?php\nsession_start();\nsession_destroy();\n"),
        ("setup.php", "<?php\nrequire_once 'includes/database.inc.php';\ncreate_database();\n"),
        ("security.php", "<?php\n$security_level = $_POST['security'];\n"),
        ("public/index.php", "<?php\nrequire '../index.php';\n"),
    ]
    for feature in (
        "sqli", "sqli_blind", "xss_r", "xss_s", "xss_d", "exec", "fi", "upload",
        "brute", "csrf", "weak_id", "csp", "javascript", "open_redirect",
    ):
        files += [
            (f"vulnerabilities/{feature}/index.php", f"<?php\n// {feature} module front end\n"),
            (f"vulnerabilities/{feature}/source/low.php", f"<?php\n// {feature} vulnerable implementation\n"),
            (f"vulnerabilities/{feature}/source/impossible.php", f"<?php\n// {feature} hardened implementation\n"),
            (f"vulnerabilities/{feature}/help/help.php", f"<?php\n// {feature} help text\n"),
        ]
    files += [
        (f"includes/library-{number}.inc.php", f"<?php\nfunction shared_helper_{number}() {{ return {number}; }}\n")
        for number in range(1, 26)
    ]
    files += [
        (f"vendor/package/p{number}/src/Thing{number}.php", f"<?php\nclass Thing{number} {{}}\n")
        for number in range(1, 26)
    ]
    return files


def test_a_php_web_app_map_limits_entries_to_high_confidence_request_paths(repository):
    """A real PHP application must not turn every executable file into an entry."""
    snapshot = repository.import_zip(make_zip(php_web_app_files()), "web-app.zip")

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
    # ...and the entries are the ones a reader would start from, not just "not those".
    assert {"index.php", "public/index.php"} <= {item["path"] for item in entrypoints}
    assert "vulnerabilities/sqli/index.php" in {item["path"] for item in entrypoints}


def test_project_map_covers_the_whole_snapshot_by_default(repository):
    """Uploading a project puts every readable file in scope; no scope picker exists."""
    snapshot = repository.import_zip(make_zip([
        ("public/index.php", "<?php echo 'ok';"),
        ("public/app.js", "fetch('/api');"),
        ("vendor/package/helper.php", "<?php function helper() { return true; }"),
    ]), "scope-map.zip")

    whole = repository.build_project_map(snapshot["id"])
    assert whole["scope"] == ["public/app.js", "public/index.php", "vendor/package/helper.php"]
    rows = {row["path"]: row for row in whole["files"]}
    assert rows["public/app.js"]["language"] == "javascript"
    assert rows["public/app.js"]["is_php"] is False
    assert rows["public/app.js"]["roles"]
    assert rows["vendor/package/helper.php"]["dependency_tree"] is True
    assert rows["public/index.php"]["dependency_tree"] is False
    assert whole["stats"]["php_files"] == 2
    assert whole["stats"]["dependency_tree_files"] == 1

    narrowed = repository.build_project_map(snapshot["id"], {"vendor/package/helper.php"})
    assert narrowed["scope"] == ["vendor/package/helper.php"]


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


def test_non_php_text_files_are_indexed_searchable_and_readable(repository):
    """A whole web project is a source tree, not only its PHP files."""
    snapshot = repository.import_zip(make_zip([
        ("app.py", "from flask import Flask\napp = Flask(__name__)\n"),
        ("static/js/app.js", "fetch('/api/todos');\n"),
        ("config/settings.yaml", "database: sqlite:///local.db\n"),
        ("docs/README.md", "# Todo\n"),
        (".env.example", "FLASK_DEBUG=1\n"),
    ]), "web.zip")
    files = {item["path"]: item for item in snapshot["files"]}
    assert files["app.py"]["kind"] == "text" and files["app.py"]["language"] == "python"
    assert files["static/js/app.js"]["language"] == "javascript"
    assert files["config/settings.yaml"]["language"] == "yaml"
    assert files[".env.example"]["language"] == "config"
    assert all(item["is_php"] is False for item in snapshot["files"])
    # No PHP means no units and no syntax index; the files are still first-class.
    assert snapshot["units"] == []
    assert snapshot["stats"]["text_files"] == 5 and snapshot["stats"]["php_files"] == 0
    assert repository.read_source(snapshot["id"], "app.py")["lines"][0]["text"] == "from flask import Flask"
    assert [item["path"] for item in repository.search_code(snapshot["id"], "sqlite")["matches"]] == ["config/settings.yaml"]
    project_map = repository.build_project_map(snapshot["id"])
    assert [(row["path"], row["language"]) for row in project_map["files"]] == [
        (".env.example", "config"),
        ("app.py", "python"),
        ("config/settings.yaml", "yaml"),
        ("docs/README.md", "markdown"),
        ("static/js/app.js", "javascript"),
    ]


def test_binary_files_are_registered_but_never_decoded(repository):
    snapshot = repository.import_zip(make_zip([
        ("assets/logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"),
        ("src/app.php", "<?php echo 1;"),
    ]), "assets.zip")
    files = {item["path"]: item for item in snapshot["files"]}
    assert files["assets/logo.png"]["kind"] == "binary"
    assert files["assets/logo.png"]["language"] == "binary"
    assert files["assets/logo.png"]["excluded"] is True
    assert snapshot["stats"]["binary_files"] == 1
    # A binary entry is never display-decoded, so it must not produce an encoding
    # warning -- that warning belongs to text files the UI would render as mojibake.
    assert "encoding_warning" not in files["assets/logo.png"]
    assert not any("logo.png" in warning for warning in snapshot["warnings"])
    with pytest.raises(ValueError, match="[Bb]inary"):
        repository.read_source(snapshot["id"], "assets/logo.png")
    assert repository.search_code(snapshot["id"], "PNG")["matches"] == []
    # Navigation keeps the binary out of the map the Planner selects paths from.
    project_map = repository.build_project_map(snapshot["id"])
    assert [row["path"] for row in project_map["files"]] == ["src/app.php"]
    assert [row["path"] for row in project_map["binary_files"]] == ["assets/logo.png"]


def test_dependency_tree_files_are_navigable_but_skipped_by_default_search(repository):
    snapshot = repository.import_zip(make_zip([
        ("index.php", "<?php require 'vendor/lib/util.php';"),
        ("vendor/lib/util.php", "<?php function util_marker() {}"),
        ("node_modules/left-pad/index.js", "module.exports = util_marker;\n"),
    ]), "dep.zip")
    assert repository.search_code(snapshot["id"], "util_marker")["matches"] == []
    widened = repository.search_code(snapshot["id"], "util_marker", include_dependencies=True)
    assert [item["path"] for item in widened["matches"]] == ["node_modules/left-pad/index.js", "vendor/lib/util.php"]
    explicit = repository.search_code(snapshot["id"], "util_marker", path="vendor/lib/util.php")
    assert [item["path"] for item in explicit["matches"]] == ["vendor/lib/util.php"]
    # Reading is never gated on the dependency tree.
    assert repository.read_source(snapshot["id"], "vendor/lib/util.php")["lines"]


def test_search_accepts_a_directory_and_narrows_to_that_subtree(repository):
    """A directory used to raise, so "search under this tree" had no way to be asked."""
    snapshot = repository.import_zip(make_zip([
        ("src/app.php", "<?php\nmarker\n"),
        ("src/lib/helper.php", "<?php\nmarker\n"),
        ("tests/test_app.php", "<?php\nmarker\n"),
        ("vendor/lib/util.php", "<?php\nmarker\n"),
    ]), "dirtree.zip")
    narrowed = repository.search_code(snapshot["id"], "marker", path="src")
    assert [item["path"] for item in narrowed["matches"]] == ["src/app.php", "src/lib/helper.php"]
    assert repository.search_code(snapshot["id"], "marker", path="src/")["matches"] == narrowed["matches"]
    # The dependency tree stays out of a directory sweep unless it is asked for,
    # exactly as it does for a whole-project search.
    assert repository.search_code(snapshot["id"], "marker", path="vendor")["matches"] == []
    widened = repository.search_code(snapshot["id"], "marker", path="vendor", include_dependencies=True)
    assert [item["path"] for item in widened["matches"]] == ["vendor/lib/util.php"]
    # Writing the project root as "." or "" searches everything rather than failing.
    whole = repository.search_code(snapshot["id"], "marker")
    for root in (".", "", "  ", "/"):
        assert repository.search_code(snapshot["id"], "marker", path=root)["matches"] == whole["matches"]
    # A path that names neither a file nor a directory is still an error.
    with pytest.raises(FileNotFoundError):
        repository.search_code(snapshot["id"], "marker", path="nope")
    # Directory narrowing is not an escape hatch: a traversal is refused as before.
    with pytest.raises(ValueError):
        repository.search_code(snapshot["id"], "marker", path="../src")


def test_search_reports_when_the_scan_limit_is_reached(repository, monkeypatch):
    monkeypatch.setattr(source, "MAX_SEARCH_FILES", 1)
    snapshot = repository.import_zip(make_zip([("a.php", "<?php\nmarker\n"), ("b.php", "<?php\nmarker\n")]), "scan.zip")
    result = repository.search_code(snapshot["id"], "marker")
    assert result["scanned_files"] == 1
    assert result["scan_truncated"] is True and result["truncated"] is True
    assert [item["path"] for item in result["matches"]] == ["a.php"]


def test_context_bundle_falls_back_when_no_php_entrypoint_exists(repository):
    """Without this fallback every worker task on a non-PHP project would be blocked."""
    snapshot = repository.import_zip(make_zip([
        ("config/settings.yaml", "debug: true\n"),
        ("docs/notes.md", "# notes\n"),
        ("src/handlers.py", "def list_todos(): pass\n"),
        ("static/css/site.css", "body { margin: 0 }\n"),
        ("vendor/lib/util.js", "module.exports = {};\n"),
    ]), "pure.zip")
    bundle = repository.build_context_bundle(snapshot["id"], {"objective": "了解项目结构"})
    assert [item["reason"] for item in bundle["excerpts"]] == ["generic_orientation_lead"] * 4
    assert [item["path"] for item in bundle["excerpts"]] == [
        "config/settings.yaml", "src/handlers.py", "docs/notes.md", "static/css/site.css",
    ]
    assert any("no PHP entry" in item.get("reason", "") for item in bundle["unresolved_dependencies"])
    # Same snapshot, same leads: orientation must not depend on dictionary luck.
    again = repository.build_context_bundle(snapshot["id"], {"objective": "了解项目结构"})
    assert [item["path"] for item in again["excerpts"]] == [item["path"] for item in bundle["excerpts"]]


def test_snapshot_index_is_parsed_once_across_many_tool_calls(repository, monkeypatch):
    snapshot = repository.import_zip(make_zip([("app.php", "<?php\necho 1;\necho 2;\n")]), "cache.zip")
    calls = {"count": 0}
    real_loads = source.json.loads

    def counting_loads(*args, **kwargs):
        calls["count"] += 1
        return real_loads(*args, **kwargs)

    fresh = SourceRepository(repository.storage)
    monkeypatch.setattr(source.json, "loads", counting_loads)
    for _ in range(50):
        fresh.read_source(snapshot["id"], "app.php")
    assert calls["count"] == 1, "the published index must be parsed once, not per tool call"


def test_project_map_scales_linearly_over_a_large_snapshot(repository):
    files = [
        (f"src/module{index // 50}/file{index}.php", "<?php\nfunction f%d() { return %d; }\n" % (index, index))
        for index in range(2000)
    ]
    snapshot = repository.import_zip(make_zip(files), "large.zip")
    start = time.perf_counter()
    project_map = repository.build_project_map(snapshot["id"])
    elapsed = time.perf_counter() - start
    assert project_map["stats"]["files"] == 2000
    assert project_map["stats"]["entrypoints"] == 0
    assert elapsed < 2.0, f"project map took {elapsed:.2f}s; has_top_level likely regressed to O(files x units)"
