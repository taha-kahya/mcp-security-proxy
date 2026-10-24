"""Pure-logic tests for in-flight call correlation bookkeeping."""

from __future__ import annotations

from mcp_security_proxy.core.proxy.routing.correlation import CallStatus, CorrelationTracker


def test_begin_then_end_removes_from_in_flight() -> None:
    tracker = CorrelationTracker()
    correlation_id = tracker.begin("server_a", "server_a__send_message")
    assert len(tracker.in_flight_for_server("server_a")) == 1

    tracker.end(correlation_id, CallStatus.COMPLETED)
    assert tracker.in_flight_for_server("server_a") == []


def test_in_flight_for_server_only_returns_matching_server() -> None:
    tracker = CorrelationTracker()
    tracker.begin("server_a", "server_a__write_record")
    tracker.begin("server_b", "server_b__write_record")

    assert len(tracker.in_flight_for_server("server_a")) == 1
    assert len(tracker.in_flight_for_server("server_b")) == 1


def test_mark_server_unknown_only_affects_that_server_and_clears_tracking() -> None:
    tracker = CorrelationTracker()
    tracker.begin("server_a", "server_a__slow_write")
    tracker.begin("server_b", "server_b__write_record")

    affected = tracker.mark_server_unknown("server_a")

    assert len(affected) == 1
    assert affected[0].status == CallStatus.UNKNOWN
    assert tracker.in_flight_for_server("server_a") == []
    assert len(tracker.in_flight_for_server("server_b")) == 1


def test_end_on_unknown_correlation_id_is_a_no_op() -> None:
    tracker = CorrelationTracker()
    tracker.end("does-not-exist", CallStatus.FAILED)  # must not raise
