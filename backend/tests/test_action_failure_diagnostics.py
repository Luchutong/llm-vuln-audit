"""Malformed actions remain unexecutable and have source-free diagnostics."""
import json

import pytest

from audit.actions import ActionIssue, check_action, extract_action


@pytest.mark.parametrize("reply", ["", " \n\t", "private model prose without an action"])
@pytest.mark.parametrize("finish_reason", ["length", "stop", None])
def test_missing_action_records_truncation_and_empty_output_without_prose(reply, finish_reason):
    action, diagnostics, issue = extract_action(reply, finish_reason)
    assert action is None and issue.category == "no_code_block"
    assert diagnostics["output_truncated"] is (finish_reason == "length")
    assert diagnostics["output_empty"] is (not bool(reply.strip()))
    assert diagnostics["block_transport"] == "none"
    assert diagnostics["closed_blocks"] == 0
    assert "private model prose" not in json.dumps(diagnostics) + str(issue)


@pytest.mark.parametrize("wrapper", ["xml", "markdown"])
@pytest.mark.parametrize("finish_reason", ["stop", "length"])
def test_unclosed_invalid_python_has_syntax_location_without_completing_code(wrapper, finish_reason):
    opening = "<code>" if wrapper == "xml" else "```python\n"
    reply = opening + "private_source_name = 'private content'\nfor row in []"
    action, diagnostics, issue = extract_action(reply, finish_reason)
    assert action is None and issue.category == "incomplete_code"
    assert diagnostics["syntax_line"] == 2
    assert diagnostics["syntax_offset"] > 0
    assert diagnostics["syntax_error_type"] == "SyntaxError"
    assert diagnostics["syntax_reason"] == "expected ':'"
    assert diagnostics["block_transport"] == wrapper
    assert diagnostics["output_truncated"] is (finish_reason == "length")
    assert "第 2 行" in issue.hint
    safe = json.dumps(diagnostics) + issue.hint
    assert "private_source_name" not in safe and "private content" not in safe


@pytest.mark.parametrize("wrapper", ["xml", "markdown"])
def test_closed_invalid_python_is_rejected_with_the_same_precise_syntax_diagnostics(wrapper):
    code = "private_source_name = 1\nfor row in []"
    reply = "<code>" + code + "</code>" if wrapper == "xml" else "```python\n" + code + "\n```"
    action, diagnostics, issue = extract_action(reply, "stop")
    assert issue is None and action == code and diagnostics["closed_blocks"] == 1
    with pytest.raises(ActionIssue) as failure:
        check_action(action, [], diagnostics)
    assert failure.value.category == "invalid_python"
    assert diagnostics["syntax_line"] == 2 and diagnostics["syntax_offset"] > 0
    assert diagnostics["syntax_error_type"] == "SyntaxError"
    assert diagnostics["syntax_reason"] == "expected ':'"
    assert "private_source_name" not in json.dumps(diagnostics) + str(failure.value)


@pytest.mark.parametrize("code,reason,error_type", [
    ("for row in []:\n", "expected an indented block", "IndentationError"),
    ("value = (1,\n", "unclosed parenthesis or bracket", "SyntaxError"),
    ("value = 'private string", "unterminated string literal", "SyntaxError"),
    ("value = '''private string", "unterminated triple-quoted string literal", "SyntaxError"),
    ("private_name = １", "invalid Python syntax", "SyntaxError"),
])
def test_safe_reasons_cover_incomplete_python_without_echoing_source(code, reason, error_type):
    action, diagnostics, issue = extract_action("<code>" + code, "length")
    assert action is None and issue.category == "incomplete_code"
    assert diagnostics["syntax_reason"] == reason
    assert diagnostics["syntax_error_type"] == error_type
    assert "private" not in json.dumps(diagnostics) + str(issue)
    assert "１" not in json.dumps(diagnostics) + str(issue)


@pytest.mark.parametrize("wrapper", ["xml", "markdown"])
@pytest.mark.parametrize("finish_reason", ["stop", None])
def test_syntactically_complete_action_accepts_provider_omitted_stop_marker(wrapper, finish_reason):
    opening = "<code>" if wrapper == "xml" else "```python\n"
    code = "final_answer({'note': 'complete'})"
    action, diagnostics, issue = extract_action(opening + code, finish_reason)
    assert issue is None and action == code
    assert diagnostics["closing_tag_omitted"] is True
    assert diagnostics["block_transport"] == wrapper
    assert diagnostics["output_truncated"] is False
    assert "syntax_error_type" not in diagnostics


@pytest.mark.parametrize("opening", ["<code>", "```python\n"])
def test_length_stop_never_promotes_a_syntactically_complete_unclosed_action(opening):
    action, diagnostics, issue = extract_action(opening + "final_answer({'note': 'partial'})", "length")
    assert action is None and issue.category == "incomplete_code"
    assert diagnostics["output_truncated"] is True
    assert "closing_tag_omitted" not in diagnostics


@pytest.mark.parametrize("wrapper", ["xml", "markdown"])
def test_quoted_transport_delimiters_remain_python_string_contents(wrapper):
    code = 'script = """<code>inner</code>\n```python\nprint("nested")\n```\n"""\nfinal_answer(script)'
    reply = "<code>\n" + code + "\n</code>" if wrapper == "xml" else "```python\n" + code + "\n```"
    action, diagnostics, issue = extract_action(reply, "stop")
    assert issue is None and action == code
    assert diagnostics["closed_blocks"] == 1 and diagnostics["block_transport"] == wrapper
    check_action(action, [], diagnostics)


def test_custom_xml_transport_records_kind_without_persisting_boundary_identifier():
    tags = ("<audit_action_private_identifier>", "</audit_action_private_identifier>")
    action, diagnostics, issue = extract_action(tags[0] + "for row in []", "length", tags)
    assert action is None and issue.category == "incomplete_code"
    assert diagnostics["block_transport"] == "xml"
    assert "private_identifier" not in json.dumps(diagnostics) + str(issue)


def test_mixed_multiple_actions_stay_ambiguous_and_cannot_execute():
    action, diagnostics, issue = extract_action("<code>value = 1</code>\n```python\nvalue = 2\n```", "stop")
    assert action is None and issue.category == "ambiguous_code_blocks"
    assert diagnostics["closed_blocks"] == 2 and diagnostics["block_transport"] == "mixed"
