# Lessons

## model_dump_json is non-deterministic for dict fields

`model_dump_json(exclude={"signature"})` uses insertion-order for `Dict[str, Any]`
fields like `context` and `ai_provenance`. This means the signing payload can differ
between signer and verifier even when the logical data is identical — producing a silent
`False` from `verify_packet` with no error or log.

**Fix**: Always build the signing payload with:

```python
import json
payload = json.dumps(
    packet.model_dump(exclude={"signature"}, mode="json"),
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
).encode("utf-8")
```

`sort_keys=True` is the load-bearing fix. `separators` and `ensure_ascii` prevent
whitespace/encoding divergence across Python versions or platforms.

Applied to: `signing.py` and `verification.py` (must always match exactly).
