"""The terminal review only gives up when the same batch rejection repeats."""
from audit.worker import final_review_stall


def test_a_changed_rejection_is_progress_not_a_stall():
    state = final_review_stall((0, ''), completed=False, failure='first contract error', limit=3)
    assert state[:2] == (1, 'first contract error') and state[2] is False
    state = final_review_stall(state[:2], completed=False, failure='next contract error', limit=3)
    assert state[:2] == (1, 'next contract error') and state[2] is False


def test_the_same_rejection_stops_the_review_at_the_limit():
    state = (0, '')
    for expected in (1, 2):
        stalls, failure, stalled = final_review_stall(state, completed=False, failure='same', limit=3)
        assert (stalls, stalled) == (expected, False)
        state = (stalls, failure)
    assert final_review_stall(state, completed=False, failure='same', limit=3)[2] is True


def test_a_completed_batch_clears_the_stall_count():
    stalls, failure, stalled = final_review_stall((2, 'same'), completed=True,
                                                  failure='ignored', limit=3)
    assert (stalls, failure, stalled) == (0, '', False)
