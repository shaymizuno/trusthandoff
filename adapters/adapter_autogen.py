from typing import Callable, Any, Dict, Optional

from trusthandoff import (
    create_attestation,
    verify_attestation,
    ExecutionAttestation,
    validate_attestation_payload,
)


class TrustHandoffAutoGenAdapter:
    def __init__(self, identity, packet_id_key: str = "packet_id"):
        self.identity = identity
        self.packet_id_key = packet_id_key

    def wrap_node(self, fn: Callable[[Dict[str, Any]], Dict[str, Any]]):
        def wrapped(state: Dict[str, Any]) -> Dict[str, Any]:
            packet_id = state.get(self.packet_id_key)
            if not packet_id:
                raise ValueError(f"Missing {self.packet_id_key!r} in state")

            try:
                result = fn(state)
            except Exception as node_exc:
                error_result = {
                    "error": str(node_exc),
                    "error_type": type(node_exc).__name__,
                }

                try:
                    attestation = create_attestation(
                        packet_id=packet_id,
                        result=error_result,
                        identity=self.identity,
                        status="ERROR",
                        reason={"node_error": True},
                    )
                except Exception as attest_exc:
                    error_result["attestation_failure"] = str(attest_exc)
                    attestation = None

                return {
                    "result": error_result,
                    "attestation": attestation,
                }

            validate_attestation_payload(result)

            try:
                attestation = create_attestation(
                    packet_id=packet_id,
                    result=result,
                    identity=self.identity,
                    status="OK",
                )
            except Exception as attest_exc:
                return {
                    "result": {
                        "original_result": result,
                        "attestation_failure": str(attest_exc),
                    },
                    "attestation": None,
                }

            return {
                "result": result,
                "attestation": attestation,
            }

        return wrapped

    def verify_node_output(
        self,
        output: Dict[str, Any],
        public_key_pem: str,
        max_age_seconds: int = 300,
        current_timestamp_ms: Optional[int] = None,
        seen_nonces: Optional[set] = None,
    ) -> bool:
        if not isinstance(output, dict):
            return False

        attestation_raw = output.get("attestation")
        result = output.get("result")

        if result is None:
            return False

        if isinstance(attestation_raw, dict):
            try:
                attestation = ExecutionAttestation.model_validate(attestation_raw)
            except Exception:
                return False
        elif isinstance(attestation_raw, ExecutionAttestation):
            attestation = attestation_raw
        else:
            return False

        verified = verify_attestation(
            attestation=attestation,
            result=result,
            public_key_pem=public_key_pem,
            max_age_seconds=max_age_seconds,
            now_ms=current_timestamp_ms,
        )

        if not verified:
            return False

        if seen_nonces is not None:
            nonce_key = (attestation.agent_pubkey_fingerprint, attestation.nonce)
            if nonce_key in seen_nonces:
                return False
            seen_nonces.add(nonce_key)

        return True
