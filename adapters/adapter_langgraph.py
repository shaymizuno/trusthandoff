import logging
from typing import Any, Callable, Dict, Optional, Set, Tuple

from trusthandoff import (
    ExecutionAttestation,
    create_attestation,
    validate_attestation_payload,
    verify_attestation,
)

logger = logging.getLogger(__name__)


class TrustHandoffLangGraphAdapter:
    def __init__(self, identity, packet_id_key: str = "packet_id"):
        self.identity = identity
        self.packet_id_key = packet_id_key

    def wrap_node(self, fn: Callable[[Dict[str, Any]], Dict[str, Any]]):
        def wrapped(state: Dict[str, Any]) -> Dict[str, Any]:
            packet_id = state.get(self.packet_id_key)
            if not packet_id:
                raise ValueError(f"Missing {self.packet_id_key!r} in state")

            attestation: Optional[ExecutionAttestation] = None
            result: Optional[Dict[str, Any]] = None

            try:
                result = fn(state)
            except Exception as node_exc:
                logger.error(
                    "Node execution failed",
                    exc_info=node_exc,
                    extra={"packet_id": packet_id},
                )

                error_result: Dict[str, Any] = {
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
                    logger.error(
                        "Attestation failed after node execution failure",
                        exc_info=attest_exc,
                        extra={"packet_id": packet_id},
                    )
                    error_result["attestation_failure"] = str(attest_exc)
                    attestation = None

                return {
                    "result": error_result,
                    "attestation": attestation,
                }

            # Programming / protocol errors must raise.
            validate_attestation_payload(result)

            try:
                attestation = create_attestation(
                    packet_id=packet_id,
                    result=result,
                    identity=self.identity,
                    status="OK",
                )
            except Exception as attest_exc:
                logger.error(
                    "Attestation failed after successful node execution",
                    exc_info=attest_exc,
                    extra={"packet_id": packet_id},
                )
                result = {
                    "original_result": result,
                    "attestation_failure": str(attest_exc),
                }
                attestation = None

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
        seen_nonces: Optional[Set[Tuple[str, int]]] = None,
    ) -> bool:
        """
        Verifies a node output dict produced by wrap_node.

        Replay protection:
        - Pass a persistent seen_nonces set across calls for the same agent/session.
        - seen_nonces is mutated in-place only after a successful verification.
        - seen_nonces is NOT thread-safe; protect it externally in concurrent contexts.
        """
        if not isinstance(output, dict):
            return False

        attestation_raw = output.get("attestation")
        result = output.get("result")

        if result is None:
            return False

        if attestation_raw is None:
            logger.warning("verify_node_output: attestation is None")
            return False

        attestation: Optional[ExecutionAttestation] = None

        if isinstance(attestation_raw, dict):
            try:
                attestation = ExecutionAttestation.model_validate(attestation_raw)
            except Exception as exc:
                logger.warning(
                    "verify_node_output: attestation deserialization failed",
                    exc_info=exc,
                )
                return False
        elif isinstance(attestation_raw, ExecutionAttestation):
            attestation = attestation_raw
        else:
            return False

        if not verify_attestation(
            attestation=attestation,
            result=result,
            public_key_pem=public_key_pem,
            max_age_seconds=max_age_seconds,
            now_ms=current_timestamp_ms,
        ):
            return False

        if seen_nonces is not None:
            nonce_key: Tuple[str, int] = (
                attestation.agent_pubkey_fingerprint,
                attestation.nonce,
            )
            if nonce_key in seen_nonces:
                logger.warning(
                    "verify_node_output: replay detected",
                    extra={"fingerprint": attestation.agent_pubkey_fingerprint},
                )
                return False
            seen_nonces.add(nonce_key)

        return True


def pretty_print_attestation(attestation: ExecutionAttestation) -> dict:
    return {
        "packet_id": attestation.packet_id,
        "status": attestation.status,
        "hash": attestation.outcome_hash[:12] + "...",
        "signed_by": attestation.signed_by,
        "timestamp_ms": attestation.timestamp_ms,
        "nonce": hex(attestation.nonce)[:10] + "...",
    }
