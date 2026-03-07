from trusthandoff import PacketDecision


def test_packet_decision_accept():
    decision = PacketDecision(
        packet_id="pk_decision_001",
        decision="ACCEPT",
        reason="Packet verified and valid",
    )

    assert decision.packet_id == "pk_decision_001"
    assert decision.decision == "ACCEPT"
    assert decision.reason == "Packet verified and valid"


def test_packet_decision_reject():
    decision = PacketDecision(
        packet_id="pk_decision_002",
        decision="REJECT",
        reason="Packet expired",
    )

    assert decision.packet_id == "pk_decision_002"
    assert decision.decision == "REJECT"
    assert decision.reason == "Packet expired"
