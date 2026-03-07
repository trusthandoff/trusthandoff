from datetime import datetime, timedelta, timezone

from trusthandoff import SignedTaskPacket, Permissions


def main():
    planner_agent = "agent:planner:alpha"
    research_agent = "agent:research:beta"

    packet = SignedTaskPacket(
        packet_id="pk_demo_001",
        task_id="task_demo_001",
        from_agent=planner_agent,
        to_agent=research_agent,
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
        nonce="demo-nonce-001",
        intent="Research company background",
        task_type="research",
        goal="Return a concise factual briefing on Example Corp",
        context={
            "company": "Example Corp",
            "jurisdiction": "US",
        },
        permissions=Permissions(
            allowed_actions=["read", "search", "summarize"],
            max_tool_calls=5,
        ),
        signature_algo="Ed25519",
        signature="demo-signature",
        public_key="demo-public-key",
    )

    print("=== TrustHandoff Demo ===")
    print(f"From: {packet.from_agent}")
    print(f"To: {packet.to_agent}")
    print(f"Intent: {packet.intent}")
    print(f"Context: {packet.context}")
    print(f"Permissions: {packet.permissions.model_dump()}")
    print()
    print("Full packet:")
    print(packet.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
