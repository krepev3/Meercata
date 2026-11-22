import json
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def test_recorded_nftables_transaction_evidence_is_schema_valid() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (ROOT / "schemas/nftables-transaction-qualification-v1.schema.json").read_text()
    )
    evidence = json.loads(
        (ROOT / "qualification-evidence/nftables-transaction-dev18.json").read_text()
    )

    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(evidence, schema)
    assert evidence["project_version"] == "2.0.0.dev18"
    assert len({item["check_id"] for item in evidence["checks"]}) == 7
