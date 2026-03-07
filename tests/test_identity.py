from trusthandoff import AgentIdentity


def test_agent_identity_generation():
    identity = AgentIdentity.generate()

    assert identity.agent_id.startswith("agent:")
    assert "BEGIN PRIVATE KEY" in identity.private_key_pem
    assert "BEGIN PUBLIC KEY" in identity.public_key_pem
