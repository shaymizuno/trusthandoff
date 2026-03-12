from pathlib import Path
import sys

from trusthandoff import AgentIdentity

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adapters.adapter_langgraph import create_packet


def test_langgraph_create_packet_accepts_capability_token():
    source = AgentIdentity.generate()
    target = AgentIdentity.generate()

    packet = create_packet(
        source_identity=source,
        target_agent_id=target.agent_id,
        state_intent="Route research task",
        state_context={"graph_state": "research_needed"},
        capability_token="demo-cap-token",
    )

    assert packet.capability_token == "demo-cap-token"
