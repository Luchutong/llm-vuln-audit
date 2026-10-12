"""What counts as "the model actually read this".

The validator is what makes an original line number in the report checkable, so it has to
be strict about code the model never saw — and it has to not invent failures, because a
citation rejected here is a real detection thrown away.
"""
from audit.evidence import seen_ranges, validate_evidence

UNIT = {"file_path": "a.php", "start_line": 1, "end_line": 20}
FILES = {"a.php": 100, "b.php": 500}


def test_the_unit_itself_counts_as_read():
    ranges = seen_ranges(UNIT, [])
    assert ("a.php", 1, 20) in ranges


def test_adjacent_reads_merge_into_one_span():
    reads = [
        {"path": "b.php", "start_line": 380, "end_line": 395},
        {"path": "b.php", "start_line": 396, "end_line": 415},
        {"path": "b.php", "start_line": 416, "end_line": 430},
        {"path": "b.php", "start_line": 430, "end_line": 440},
    ]
    ranges = seen_ranges(UNIT, reads)
    assert ("b.php", 380, 440) in ranges

    # The citation the model actually made, which used to be rejected as never read.
    verified, problems = validate_evidence(
        [{"path": "b.php", "start_line": 380, "end_line": 440}], FILES, ranges
    )
    assert problems == []
    assert verified == [{"path": "b.php", "start_line": 380, "end_line": 440}]


def test_a_gap_is_never_papered_over():
    reads = [
        {"path": "b.php", "start_line": 10, "end_line": 20},
        {"path": "b.php", "start_line": 30, "end_line": 40},
    ]
    ranges = seen_ranges(UNIT, reads)
    assert ("b.php", 10, 40) not in ranges
    # Lines 21-29 were never returned by any tool, so citing them must still fail.
    _, problems = validate_evidence(
        [{"path": "b.php", "start_line": 15, "end_line": 35}], FILES, ranges
    )
    assert problems and "never read" in problems[0]


def test_reads_are_not_merged_across_files():
    reads = [
        {"path": "a.php", "start_line": 30, "end_line": 40},
        {"path": "b.php", "start_line": 41, "end_line": 50},
    ]
    ranges = seen_ranges(UNIT, reads)
    assert ("a.php", 30, 40) in ranges
    assert ("b.php", 41, 50) in ranges
    assert not any(path == "a.php" and start == 30 and end == 50 for path, start, end in ranges)


def test_bad_citations_are_dropped_and_good_ones_kept():
    ranges = seen_ranges(UNIT, [{"path": "a.php", "start_line": 25, "end_line": 30}])
    verified, problems = validate_evidence(
        [
            {"path": "a.php", "start_line": 5, "end_line": 10},
            {"path": "b.php", "start_line": 1, "end_line": 400},   # never read
            {"path": "c.php", "start_line": 1, "end_line": 2},     # not in the snapshot
            {"path": "a.php", "start_line": 25, "end_line": 30},
        ],
        FILES,
        ranges,
    )
    assert verified == [
        {"path": "a.php", "start_line": 5, "end_line": 10},
        {"path": "a.php", "start_line": 25, "end_line": 30},
    ]
    assert len(problems) == 2


def test_evidence_beyond_the_end_of_a_file_is_rejected():
    ranges = seen_ranges(UNIT, [{"path": "a.php", "start_line": 1, "end_line": 200}])
    verified, problems = validate_evidence(
        [{"path": "a.php", "start_line": 90, "end_line": 150}], FILES, ranges
    )
    assert verified == []
    assert problems and "exceed" in problems[0]


def test_no_evidence_at_all_is_not_a_pass():
    verified, problems = validate_evidence([], FILES, seen_ranges(UNIT, []))
    assert verified == []
    assert problems
