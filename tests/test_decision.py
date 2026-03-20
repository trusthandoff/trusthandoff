import pytest
from pydantic import ValidationError

from trusthandoff.decision import PacketDecision


def test_packet_decision_truncates_oversized_string():
    decision = PacketDecision(
        packet_id="pk-1",
        decision="REJECT",
        reason="expired",
        details={"message": "x" * 300},
    )
    assert decision.details["message"].endswith("...")
    assert len(decision.details["message"]) == 259


def test_packet_decision_sanitizes_bytes():
    decision = PacketDecision(
        packet_id="pk-1",
        decision="REJECT",
        reason="expired",
        details={"blob": b"abcdef"},
    )
    assert decision.details["blob"].startswith("<bytes:")
    assert decision.details["blob"].endswith("...>")


def test_packet_decision_limits_nested_depth():
    decision = PacketDecision(
        packet_id="pk-1",
        decision="REJECT",
        reason="expired",
        details={"a": {"b": {"c": {"d": {"e": "too_deep"}}}}},
    )
    assert decision.details["a"]["b"]["c"]["d"] == "<max_depth_reached>"


def test_packet_decision_truncates_large_list():
    decision = PacketDecision(
        packet_id="pk-1",
        decision="REJECT",
        reason="expired",
        details={"items": list(range(30))},
    )
    assert decision.details["items"][-1] == "<truncated>"


def test_packet_decision_truncates_large_dict():
    payload = {f"k{i}": i for i in range(30)}
    decision = PacketDecision(
        packet_id="pk-1",
        decision="REJECT",
        reason="expired",
        details=payload,
    )
    assert decision.details["<truncated>"] is True


def test_packet_decision_is_frozen():
    decision = PacketDecision(
        packet_id="pk-1",
        decision="ACCEPT",
        reason="ok",
    )
    with pytest.raises(ValidationError):
        decision.reason = "changed"


def test_packet_decision_forbids_extra_fields():
    with pytest.raises(ValidationError):
        PacketDecision(
            packet_id="pk-1",
            decision="ACCEPT",
            reason="ok",
            secret="forbidden",
        )


def test_packet_decision_model_dump_json_safe():
    decision = PacketDecision(
        packet_id="pk-1",
        decision="REJECT",
        reason="expired",
        details={
            "agents": ["a", "b"],
            "blob": b"abcdef",
            "obj": object(),
        },
    )
    payload = decision.model_dump(mode="json")
    assert payload["details"]["agents"] == ["a", "b"]
    assert payload["details"]["blob"].startswith("<bytes:")
    assert payload["details"]["obj"].startswith("<unsupported:")
