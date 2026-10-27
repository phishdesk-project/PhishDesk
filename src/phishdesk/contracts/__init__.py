"""Versioned cross-track contracts. A valid proposal is never an approval."""

from phishdesk.contracts.v1 import ActionRequestV1, EvidenceV1, VerdictV1, validate_exchange

__all__ = ["ActionRequestV1", "EvidenceV1", "VerdictV1", "validate_exchange"]
