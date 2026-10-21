"""Validation for the 30-challenge lab and its prompt variants."""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

from tree_sitter import Language, Parser
from tree_sitter_php import language_php

from audit.lab_prompts import LAB_KINDS, LAB_P0, LAB_P1, LAB_P2, LAB_P0_LITE, LAB_P1_LITE

PROJECT = pathlib.Path(__file__).resolve().parents[2]
LAB_ROOT = PROJECT / "demo" / "lab30"
MANIFEST = json.loads((LAB_ROOT / "manifest.json").read_text(encoding="utf-8"))


def _load_runner():
    spec = importlib.util.spec_from_file_location("lab_rounds", PROJECT / "scripts" / "lab_rounds.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lab_rounds():
    return _load_runner()


def test_manifest_has_exactly_thirty_challenges():
    assert len(MANIFEST["challenges"]) == 30
    ids = [item["id"] for item in MANIFEST["challenges"]]
    assert len(set(ids)) == 30


def test_manifest_files_exist_and_parse():
    parser = Parser(Language(language_php()))
    kinds = {kind for kind, _ in LAB_KINDS}
    for item in MANIFEST["challenges"]:
        path = LAB_ROOT / item["file"]
        assert path.is_file(), f"missing {item['file']}"
        tree = parser.parse(path.read_bytes())
        assert not tree.root_node.has_error, f"parse error in {item['file']}"
        assert item["kind"] in kinds, f"unknown kind {item['kind']}"
        assert item["difficulty"] in (1, 2, 3)
    for helper in MANIFEST.get("helpers", []):
        assert (LAB_ROOT / helper).is_file(), f"missing helper {helper}"


def test_every_kind_has_a_challenge():
    kinds = {item["kind"] for item in MANIFEST["challenges"]}
    # At least the diversity the coursework asks for; the full list need not all appear.
    for required in ("sqli", "xss", "cmdi", "broken_access_control", "business_logic"):
        assert required in kinds


def test_prompt_variants_list_the_allowed_kinds():
    for prompt in (LAB_P0, LAB_P1, LAB_P2, LAB_P0_LITE, LAB_P1_LITE):
        for slug, _label in LAB_KINDS:
            assert slug in prompt


def test_prompts_differ_in_rigour(lab_rounds):
    assert len(set(lab_rounds.PROMPTS)) == 5
    assert "输入来源 → 传播路径 → 危险操作" not in LAB_P0
    assert "输入来源 → 传播路径 → 危险操作" in LAB_P1
    assert "触发前提" in LAB_P2
    # The two "改弱" baselines sit below P0: no strict chain and no POC control.
    for prompt in (LAB_P0_LITE, LAB_P1_LITE):
        assert "输入来源 → 传播路径 → 危险操作" not in prompt
        assert "正常输入与攻击输入对照" not in prompt
    assert "防护" in LAB_P1_LITE
    assert "防护" not in LAB_P0_LITE


def test_scoring_totals(lab_rounds):
    challenge = {"id": "ch01", "kind": "sqli", "difficulty": 1}
    hit = lab_rounds.score(challenge, [{"kind": "sqli"}])
    assert (hit["tp"], hit["fp"], hit["fn"]) == (1, 0, 0)

    miss = lab_rounds.score(challenge, [])
    assert (miss["tp"], miss["fp"], miss["fn"]) == (0, 0, 1)

    wrong = lab_rounds.score(challenge, [{"kind": "xss"}, {"kind": "cmdi"}])
    assert (wrong["tp"], wrong["fp"], wrong["fn"]) == (0, 2, 1)

    total = lab_rounds.totals([hit, miss, wrong])
    assert (total["tp"], total["fp"], total["fn"]) == (1, 2, 2)


def test_runner_builds_a_zip_with_all_files(lab_rounds):
    data = lab_rounds.build_zip(LAB_ROOT)
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = set(archive.namelist())
    expected = {item["file"] for item in MANIFEST["challenges"]} | set(MANIFEST["helpers"]) | {"manifest.json"}
    assert expected <= names
